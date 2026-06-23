# 实现gRPC接口
import asyncio
from datetime import datetime
import json
import logging
import grpc
from queue import Queue, Empty

import pytz
from agent_server.proto import agent_pb2 as pb2
from agent_server.proto import agent_pb2_grpc as pb2_grpc
from flask_server.models import (
    MonitorAlert,
    SessionFactory,
    ClientInfo,
    UrlAlertInfo,
    AgentControlLog,
)

max_concurrent_tasks = 5  # 限制最大并发数


def create_db_session():
    return SessionFactory()


class AgentServiceServicer(pb2_grpc.AgentServiceServicer):
    def __init__(self, server):
        self.server = server
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)

    def RegisterHost(self, request, context):
        trailing_metadata = dict(context.trailing_metadata())
        agent_id = trailing_metadata.get("agent_id")
        if not agent_id:
            return pb2.Feedback(successful=False, message="Id not exist")

        session = create_db_session()
        try:
            agent = session.query(ClientInfo).filter_by(client_id=agent_id).first()
            if not agent:
                return pb2.Feedback(successful=False, message="Id not exist")

            agent.register_time = datetime.now()
            agent.last_beat_time = datetime.now()
            agent.status = "online"
            agent.hostname = request.hostname
            client_name = agent.client_name

            session.add(agent)
            session.commit()
        except Exception as e:
            session.rollback()
            self.server.logger.error(f"agent注册时间更新失败 agent_id:{agent_id} {context.peer()} {e}")
            return pb2.Feedback(successful=False, message=str(e))
        finally:
            session.close()

        runtime_agent = self.server.agent_list.get(agent_id)
        if runtime_agent:
            runtime_agent.status = "online"
            runtime_agent.hostname = request.hostname
        self.server.logger.info(f"上线通知 ID:{agent_id}, Name:{client_name}, IP:{context.peer()}")

        return pb2.Feedback(successful=True)

    def ReprotState(self, request, context):
        trailing_metadata = dict(context.trailing_metadata())
        agent_id = trailing_metadata.get("agent_id")

        info = {
            "cpu_used_percent": request.cpu,
            "mem_used": request.memory,
            "disk_used": request.disk,
            "network_out": request.network,
            "load_avg1": request.load,
            "io": request.io,
            "time_stamp": request.time,
        }
        if agent_id in self.server.agent_list:
            self.server.agent_list[agent_id].status = "online"
        self.server.logger.debug(f"状态上报： agent_id:{agent_id} {context.peer()} {info}")

        session = create_db_session()
        try:
            agent = session.query(ClientInfo).filter_by(client_id=agent_id).first()
            if agent:
                agent.last_beat_time = datetime.now()
                agent.status = "online"
                session.add(agent)
                session.commit()
                self.server.logger.debug(f"心跳时间更新：{agent.client_name}-{agent.last_beat_time}")
        except Exception as e:
            session.rollback()
            self.server.logger.error(f"agent心跳时间更新失败 agent_id:{agent_id} {context.peer()} {e}")
        finally:
            session.close()

        return pb2.Feedback(successful=True)

    def RequestCmd(self, request, context):
        trailing_metadata = dict(context.trailing_metadata())
        agent_id = trailing_metadata.get("agent_id", "0")

        if agent_id not in self.server.agent_list:
            context.abort(grpc.StatusCode.NOT_FOUND, "Agent not found")

        agent = self.server.agent_list[agent_id]
        agent.task_stream = context
        self.server.agent_list[agent_id].status = "online"
        queue = self.server.commond_queue.setdefault(agent_id, Queue())

        try:
            while agent.task_stream.is_active():
                try:
                    cmd_message = queue.get(timeout=20)
                    self.server.logger.info(f"读取到命令\n:{cmd_message}")
                except Empty:
                    cmd_message = pb2.Cmd(id=0, type=1, data="")
                yield cmd_message
        except grpc.RpcError as e:
            self.server.logger.info(f"Agent {agent_id} 连接已断开: {e}")
        except Exception as e:
            self.server.logger.error(f"处理请求时出错：{e}")
        finally:
            self.server.logger.error("任务流结束，客户端已断开")
            self.server.agent_list[agent_id].status = "offline"
            self.server.logger.info(f"下线通知: ID {request.id}, Name {agent.client_name}, IP {context.peer()}")

            session = create_db_session()
            try:
                query = session.query(ClientInfo).filter_by(client_id=agent_id).first()
                if query:
                    query.status = "offline"
                    session.add(query)
                    session.commit()
            except Exception as e:
                session.rollback()
                self.server.logger.error(f"agent offline状态更新失败 {e}")
            finally:
                session.close()

    def ReturnCmdResult(self, request, context):
        if request.id != 0:
            self.server.logger.info(f"Received command result: ID {request.id}, success: {request.successful}")

            session = create_db_session()
            try:
                record = session.query(AgentControlLog).filter_by(operate_id=request.id).first()
                if record:
                    record.success = request.successful
                    record.result = request.data
                    record.delay = request.delay
                    record.finish_at = datetime.now()
                    session.add(record)
                    session.commit()
            except Exception as e:
                session.rollback()
                self.server.logger.error(f"命令结果记录失败，ID {request.id}, {e}")
                return pb2.Feedback(successful=False)
            finally:
                session.close()

        return pb2.Feedback(successful=True)

    def ReportMonitorEvent(self, request, context):
        self.server.logger.info(f"Received monitor event {request.eventType} {request.timeStamp} {request.path}")
        trailing_metadata = dict(context.trailing_metadata())
        agent_id = trailing_metadata.get("agent_id", "0")
        detail_json = json.loads(request.jsonData)

        record = MonitorAlert()
        record.client_id = agent_id
        record.ip = context.peer().split(":")[1]
        record.cwd = detail_json.get("cwd", "")
        record.path = request.path
        record.proctitle = detail_json.get("pproc", "") + ":" + "" + detail_json.get("pid", "") + ":" + detail_json.get("proc", "")

        utc_time = datetime.fromtimestamp(request.timeStamp, tz=pytz.utc)
        beijing_tz = pytz.timezone("Asia/Shanghai")
        record.trigger_time = utc_time.astimezone(beijing_tz)

        session = create_db_session()
        try:
            session.add(record)
            session.commit()
        except Exception as e:
            session.rollback()
            self.server.logger.error(f"记录告警出错,{e}")
            return pb2.Feedback(successful=False)
        finally:
            session.close()

        return pb2.Feedback(successful=True)

    def ReportUrlEvent(self, request, context):
        utc_time = datetime.fromtimestamp(request.timeStamp, tz=pytz.utc)
        beijing_tz = pytz.timezone("Asia/Shanghai")
        dt = utc_time.astimezone(beijing_tz)

        details = {}
        try:
            details = json.loads(request.details)
            self.server.logger.debug(f"Details: {details}")
        except json.JSONDecodeError as e:
            self.server.logger.debug(f"解析 details 时出错: {e}")

        alert = UrlAlertInfo()
        alert.trigger_time = dt
        alert.report_time = datetime.now()
        alert.honeypoint_id = 1
        alert.src_ip = request.ip
        alert.dst_ip = "127.0.0.1"
        alert.fingerprint = request.fingerprint
        alert.info = details
        alert.url = details.get("path")

        session = create_db_session()
        try:
            session.add(alert)
            session.commit()
        except Exception:
            session.rollback()
            self.server.logger.error("告警存储出错")
            return pb2.Feedback(successful=False)
        finally:
            session.close()

        logging.info("告警存储成功")
        return pb2.Feedback(successful=True)
