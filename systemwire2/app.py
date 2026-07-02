import logging
import os
import signal
import sys
import threading
import time
import faulthandler

try:
    faulthandler.register(signal.SIGUSR1, all_threads=True, chain=False)
except Exception:
    pass

from flask_server.flask_app import flask_app, init_flask_server
from flask_server.views import repair_honeypot_delivery_chain
from agent_server.server import create_grpc_server, run_grpc_server
from config.config import *


base_dir = os.path.abspath(os.path.dirname(__file__))
log_dir = os.path.join(base_dir, "log")


def _startup_repair_enabled():
    value = os.getenv("SYSTEMWIRE_STARTUP_REPAIR", "0").strip().lower()
    return value in ("1", "true", "yes", "on")


def _run_startup_repair_async():
    with flask_app.app_context():
        try:
            repair_honeypot_delivery_chain()
            flask_app.logger.info("startup honeypot delivery chain repair executed")
        except Exception as exc:
            flask_app.logger.warning("startup honeypot delivery chain repair failed: %s", exc)


if __name__ == "__main__":
    logging.info("starting SystemWire2 service...")

    try:
        init_flask_server()
        create_grpc_server()

        if _startup_repair_enabled():
            repair_thread = threading.Thread(
                target=_run_startup_repair_async,
                daemon=True,
                name="startup-honeypot-repair",
            )
            repair_thread.start()
        else:
            flask_app.logger.info(
                "startup honeypot delivery chain repair skipped; "
                "set SYSTEMWIRE_STARTUP_REPAIR=1 to enable"
            )

        logging.info("starting gRPC server...")
        grpc_thread = threading.Thread(
            target=run_grpc_server,
            daemon=True,
        )
        grpc_thread.start()
        os.environ["GRPC_INITIALIZED"] = "true"
        logging.info("gRPC server started on port %s", GRPC_PORT)

        flask_app.config["TEMPLATES_AUTO_RELOAD"] = True
        flask_app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)

    except KeyboardInterrupt:
        logging.info("received stop signal, shutting down server...")
        sys.exit(0)
    except Exception as e:
        logging.error("server runtime error: %s", str(e))
        sys.exit(1)
