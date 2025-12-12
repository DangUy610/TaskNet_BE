from django.urls import path
from . import views

urlpatterns = [
    # ============================================================
    # 🏢 WORKSPACES
    # ============================================================
    path('workspaces/', views.WorkspaceListCreateView.as_view(), name='workspace-list-create'),
    path('workspaces/<int:workspace_id>/', views.WorkspaceDetailView.as_view(), name='workspace-detail'),
    path('workspaces/<int:workspace_id>/members/', views.WorkspaceMembersView.as_view(), name='workspace-members'),
    path('workspaces/<int:workspace_id>/transfer-ownership/', views.WorkspaceTransferOwnershipView.as_view(), name='workspace-transfer-ownership'),
    
    # Nested Boards (Tạo & Lấy danh sách board trong workspace)
    path('workspaces/<int:workspace_id>/boards/', views.BoardListCreateView.as_view(), name='workspace-board-list'),
    path('workspaces/<int:workspace_id>/boards/<int:board_id>/', views.BoardDetailView.as_view(), name='board-detail'),
    path('workspaces/<int:workspace_id>/boards/<int:board_id>/transfer-owner/', views.BoardTransferOwnershipView.as_view(), name='board-transfer-owner'),

    # ============================================================
    # 📋 BOARDS (Direct Actions & Settings)
    # ============================================================
    path('boards/closed/', views.ClosedBoardsListView.as_view(), name='board-closed-list'),
    path('boards/<int:board_id>/lists/', views.ListsCreateView.as_view(), name='board-list-create'),
    path('boards/<int:board_id>/labels/', views.BoardLabelListCreateView.as_view(), name='board-labels'),
    path('boards/<int:board_id>/members/', views.BoardMembersView.as_view(), name='board-members'),
    path('boards/<int:board_id>/planner/', views.BoardPlannerDataView.as_view(), name='board-planner-data'),

    # Sharing & Invitations
    path('boards/<int:board_id>/share-link/', views.BoardShareLinkView.as_view(), name='board-share-link'),
    path('boards/<int:board_id>/invitations/', views.BoardEmailInvitationView.as_view(), name='board-email-invite'),
    path('boards/join/<uuid:token>/', views.BoardJoinByLinkView.as_view(), name='board-join-by-link'),

    # ============================================================
    # 📑 LISTS
    # ============================================================
    path('lists/<int:pk>/', views.ListDetailView.as_view(), name='list-detail'),
    path('lists/<int:list_id>/cards/', views.CardListCreateView.as_view(), name='list-card-create'),

    # ============================================================
    # 🎫 CARDS (Core)
    # ============================================================
    path('cards/', views.InboxCardCreateView.as_view(), name='card-inbox-create'),
    path('cards/batch-update/', views.CardBatchUpdateView.as_view(), name='card-batch-update'),
    path('cards/<int:pk>/', views.CardDetailView.as_view(), name='card-detail'),

    # Card: Comments & Activities
    path('cards/<int:card_id>/comments/', views.CardCommentsView.as_view(), name='card-comments'),
    path('labels/', views.LabelCreateView.as_view(), name='label-create'),
    path('labels/<int:label_id>/', views.LabelDetailView.as_view(), name='label-detail'),
    
    path('cards/<int:card_id>/activities/', views.CardActivityView.as_view(), name='card-activities'),

    # Card: Attachments
    path('cards/<int:card_id>/attachments/', views.CardAttachmentsView.as_view(), name='card-attachments'),
    
    # Card: Members & Watchers
    path('cards/<int:card_id>/assignees/', views.CardAssigneeListView.as_view(), name='card-assignees'),
    path('cards/<int:card_id>/assignees/set/', views.CardAssigneeBulkSetView.as_view(), name='card-assignees-set'),
    path('cards/<int:card_id>/watchers/', views.CardWatcherListView.as_view(), name='card-watchers'),
    path('cards/<int:card_id>/watchers/set/', views.CardWatcherBulkSetView.as_view(), name='card-watchers-set'),

    # Card: Checklists
    path('cards/<int:card_id>/checklists/', views.CardChecklistListView.as_view(), name='card-checklists'),

    # ============================================================
    # 🧩 SUB-RESOURCES (Comments, Labels, Attachments, Checklists)
    # ============================================================
    path('comments/<int:comment_id>/', views.CommentDetailView.as_view(), name='comment-detail'),
    path('labels/<int:label_id>/', views.LabelDetailView.as_view(), name='label-detail'),
    path('attachments/<int:attachment_id>/', views.AttachmentDetailView.as_view(), name='attachment-detail'),

    # Checklist Items Internal Actions
    path('checklists/<int:pk>/', views.ChecklistDetailView.as_view(), name='checklist-detail'),
    path('checklists/<int:pk>/reorder-items/', views.ReorderItemsView.as_view(), name='checklist-reorder'),
    path('checklists/<int:checklist_id>/items/', views.ChecklistItemListView.as_view(), name='checklist-items'),
    
    path('checklist-items/<int:pk>/', views.ChecklistItemDetailView.as_view(), name='checklist-item-detail'),
    path('checklist-items/<int:pk>/convert-to-card/', views.ConvertItemToCardView.as_view(), name='checklist-item-convert'),

    # ============================================================
    # 🔔 NOTIFICATIONS
    # ============================================================
    path("notifications/", views.NotificationListView.as_view(), name="notification-list"),
    path("notifications/create/", views.NotificationCreateView.as_view(), name="notification-create"),
    path("notifications/unread-count/", views.NotificationUnreadCountView.as_view(), name="notification-unread-count"),
    path("notifications/mark-all-read/", views.NotificationMarkAllReadView.as_view(), name="notification-mark-all-read"),
    path("notifications/<int:pk>/", views.NotificationDetailView.as_view(), name="notification-detail"),
    path("notifications/<int:pk>/read/", views.NotificationMarkReadView.as_view(), name="notification-mark-read"),

    # ============================================================
    # 👤 USERS / UTILS
    # ============================================================
    path('users/search/', views.UserSearchView.as_view(), name='user-search'),
    path("activity/me/", views.UserActivityListView.as_view(), name="user-activity"),

]