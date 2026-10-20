"""Serialize resource-heavy interactive analysis on the management process."""
from functools import wraps
from threading import Lock
from flask import jsonify

_analysis_lock = Lock()


def one_analysis_at_a_time(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not _analysis_lock.acquire(blocking=False):
            return jsonify({"code": 1, "message": "已有分析任务运行中，请稍后重试。"}), 429
        try:
            return function(*args, **kwargs)
        except ValueError as error:
            return jsonify({"code": 1, "message": str(error)}), 400
        finally:
            _analysis_lock.release()
    return wrapped
