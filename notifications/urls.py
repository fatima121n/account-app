from tkinter import N
from django.urls import path
from . views import NotificationListView, MarkNotificationReadView, DeleteNotificationView

urlpatterns = [
    path('', NotificationListView.as_view(), name='notification-list'),
    path('<int:pk>/read/', MarkNotificationReadView.as_view(), name='notification-read'),
    path('<int:pk>/delete/', DeleteNotificationView.as_view(), name='delete-notification'),
]
