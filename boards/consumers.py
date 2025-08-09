import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import Card, List
from .serializers import CardSerializer, ListSerializer

class BoardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.board_id = self.scope['url_route']['kwargs']['board_id']
        self.group_name = f'board_{self.board_id}'

        # Tham gia nhóm WebSocket
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Rời nhóm
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # Không xử lý dữ liệu từ client trong trường hợp này
        pass

    async def card_update(self, event):
        # Gửi thông báo cập nhật thẻ tới client
        cards = Card.objects.filter(list__isnull=True).order_by('position')
        lists = List.objects.filter(board_id=self.board_id).order_by('position')
        lists_data = []
        for list_obj in lists:
            cards_in_list = Card.objects.filter(list=list_obj).order_by('position')
            list_data = ListSerializer(list_obj).data
            list_data['cards'] = CardSerializer(cards_in_list, many=True).data
            lists_data.append(list_data)

        await self.send(text_data=json.dumps({
            'type': 'card_update',
            'cards': CardSerializer(cards, many=True).data,
            'lists': lists_data
        }))