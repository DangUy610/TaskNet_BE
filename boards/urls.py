from django.urls import path
from .views import (
    BoardListCreateView,
    ListsCreateView,
    CardListCreateView,
    BoardDetailView,
    CardDetailView,
    ListDetailView,
    InboxCardCreateView,
    BoardLabelsView,
    BoardMembersView,
    LabelCreateView,
    LabelDetailView,
    CardBatchUpdateView,
    ClosedBoardsListView,
    BoardShareLinkView,
    BoardJoinByLinkView,
    CardCommentsView,
    CommentDetailView

)

urlpatterns = [
    #Board
    path('boards/', BoardListCreateView.as_view(), name='board-list-create'),

    # List (theo board)
    path('boards/<int:board_id>/lists/', ListsCreateView.as_view(), name='list-list-create'),

    # Card (theo list)
    path('lists/<int:list_id>/cards/', CardListCreateView.as_view(), name='card-list-create'),
    path('boards/<int:board_id>/', BoardDetailView.as_view(), name='board-detail'),
    # Card va List thay doi vi tri khi f5 va save card list
    path('cards/<int:card_id>/', CardDetailView.as_view(), name='card-detail'),
    path('lists/<int:list_id>/', ListDetailView.as_view(), name='list-detail'),

    path('cards/', InboxCardCreateView.as_view(), name='card-create-inbox'),

    path('boards/<int:board_id>/labels/', BoardLabelsView.as_view()),

    path('boards/<int:board_id>/members/', BoardMembersView.as_view(), name='board_members'),

    path('boards/<int:board_id>/labels/', LabelCreateView.as_view(), name='label-create'),
    path('labels/<int:label_id>/', LabelDetailView.as_view(), name='label-detail'),

    path('cards/batch-update/', CardBatchUpdateView.as_view(), name='card-batch-update'),

    path('boards/closed/', ClosedBoardsListView.as_view(), name='closed-board-list'),

    path('boards/<int:board_id>/share-link/', BoardShareLinkView.as_view(), name='board-share-link'),
    path('boards/join/<uuid:token>/', BoardJoinByLinkView.as_view(), name='board-join-by-link'),

    path('cards/<int:card_id>/comments/', CardCommentsView.as_view()),
    path('comments/<int:comment_id>/', CommentDetailView.as_view()),

]
