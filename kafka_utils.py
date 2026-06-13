import json
import logging
import asyncio
from typing import Callable, Any, Awaitable
try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
MCP_EVENTS_TOPIC = "mcp-events"

class KafkaStreamingClient:
    def __init__(self):
        self.producer = None
        self.consumer = None
        self.is_connected = False
        self.consume_task = None

    async def connect_producer(self):
        if not KAFKA_AVAILABLE:
            logger.warning("aiokafka not installed. Kafka streaming disabled.")
            return False
            
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else b''
            )
            await self.producer.start()
            self.is_connected = True
            logger.info("Connected to Kafka Producer.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Kafka Producer: {e}")
            self.is_connected = False
            return False

    async def disconnect_producer(self):
        if self.producer:
            await self.producer.stop()
            self.is_connected = False

    async def produce_event(self, session_id: str, event_data: dict):
        if self.is_connected and self.producer:
            try:
                # Partition by session_id to maintain chronological order
                await self.producer.send_and_wait(
                    topic=MCP_EVENTS_TOPIC, 
                    value=event_data, 
                    key=session_id
                )
            except Exception as e:
                logger.error(f"Failed to produce to Kafka: {e}")
        else:
            logger.warning("Kafka Producer not connected. Dropping event.")

    async def start_consumer(self, callback: Callable[[dict], Awaitable[None]]):
        if not KAFKA_AVAILABLE:
            return False

        try:
            self.consumer = AIOKafkaConsumer(
                MCP_EVENTS_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                key_deserializer=lambda k: k.decode('utf-8') if k else '',
                group_id="mcp-taint-tracker-workers",
                auto_offset_reset="latest"
            )
            await self.consumer.start()
            logger.info("Connected to Kafka Consumer.")
            
            async def consume_loop():
                try:
                    async for msg in self.consumer:
                        try:
                            await callback(msg.value)
                        except Exception as cb_err:
                            logger.error(f"Error in Kafka consumer callback: {cb_err}")
                except asyncio.CancelledError:
                    logger.info("Kafka consumer loop cancelled.")
                finally:
                    await self.consumer.stop()
                    
            self.consume_task = asyncio.create_task(consume_loop())
            return True
        except Exception as e:
            logger.error(f"Failed to start Kafka Consumer: {e}")
            return False
            
    async def stop_consumer(self):
        if self.consume_task:
            self.consume_task.cancel()
        if self.consumer:
            await self.consumer.stop()

streaming_client = KafkaStreamingClient()
