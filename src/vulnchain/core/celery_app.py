"""Celery application configuration for background task processing"""
from celery import Celery
from src.vulnchain.core.config import settings

# Create Celery instance
celery_app = Celery(
    "vulnchain",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.fuzzing_tasks",
        "app.tasks.report_tasks",
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task execution settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task result settings
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={
        "master_name": "mymaster",
        "visibility_timeout": 3600,
    },
    
    # Task routing
    task_routes={
        "app.tasks.scan_tasks.*": {"queue": "scans"},
        "app.tasks.fuzzing_tasks.*": {"queue": "fuzzing"},
        "app.tasks.report_tasks.*": {"queue": "reports"},
    },
    
    # Worker settings
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    
    # Task time limits
    task_time_limit=3600,  # Hard limit: 1 hour
    task_soft_time_limit=3300,  # Soft limit: 55 minutes
    
    # Task retry settings
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    
    # Beat schedule (for periodic tasks)
    beat_schedule={
        "cleanup-expired-sessions": {
            "task": "app.tasks.scan_tasks.cleanup_expired_sessions",
            "schedule": 3600.0,  # Run every hour
        },
        "cleanup-old-findings": {
            "task": "app.tasks.scan_tasks.cleanup_old_findings",
            "schedule": 86400.0,  # Run daily
        },
    },
)

# Task annotations for specific task configurations
celery_app.conf.task_annotations = {
    "app.tasks.scan_tasks.run_full_scan": {
        "rate_limit": "10/m",  # Max 10 full scans per minute
        "time_limit": 7200,  # 2 hours for full scans
    },
    "app.tasks.fuzzing_tasks.run_fuzzing_campaign": {
        "rate_limit": "20/m",
        "time_limit": 3600,
    },
    "app.tasks.report_tasks.generate_pdf_report": {
        "rate_limit": "30/m",
        "time_limit": 600,  # 10 minutes for PDF generation
    },
}


def get_celery_app() -> Celery:
    """
    Get Celery application instance.
    
    Returns:
        Celery application instance
    """
    return celery_app
