from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery("audit_platform", broker=settings.redis_url, backend=settings.redis_url, include=["app.tasks"])
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "daily-data-retention": {
            "task": "app.tasks.cleanup_retained_data",
            "schedule": crontab(hour=3, minute=0),
        }
    },
)
