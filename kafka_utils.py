import json
import os
import logging
import asyncio
import socket
from typing import Callable, Any, Awaitable
try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer, ConsumerRebalanceListener
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
MCP_EVENTS_TOPIC = "mcp-events"


def _generate_instance_id() -> str:
    """Generate a unique consumer instance ID for static group membership."""
    hostname = socket.gethostname()
    pid = os.getpid()
    return f"{hostname}-{pid}"


class RebalanceListener(ConsumerRebalanceListener):
    """Tracks partition assignment state for consumer readiness."""

    def __init__(self):
        self.consumer_ready = False

    def on_partitions_assigned(self, assigned):
        self.consumer_ready = len(assigned) > 0
        logger.info("Partitions assigned: %s. Consumer ready: %s", assigned, self.consumer_ready)

    def on_partitions_revoked(self, revoked):
        self.consumer_ready = False
        logger.info("Partitions revoked: %s", revoked)


class KafkaStreamingClient:
    def __init__(self):
        self.producer = None
        self.consumer = None
        self.is_connected = False
        self.consume_task = None
        self._listener = None
        self.instance_id = _generate_instance_id()

    @property
    def consumer_ready(self):
        return self._listener is not None and self._listener.consumer_ready

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
            raise RuntimeError("aiokafka not installed. Cannot start consumer.")

        self._listener = RebalanceListener()
        self.consumer = AIOKafkaConsumer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            key_deserializer=lambda k: k.decode('utf-8') if k else '',
            group_id="mcp-taint-tracker-workers",
            auto_offset_reset="latest",
            session_timeout_ms=45000,
            heartbeat_interval_ms=15000,
            max_poll_interval_ms=600000,
        )
        await self.consumer.start()
        self.consumer.subscribe([MCP_EVENTS_TOPIC], listener=self._listener)
        logger.info("Connected to Kafka Consumer (instance=%s).", self.instance_id)

        async def consume_loop():
            try:
                async for msg in self.consumer:
                    try:
                        await callback(msg.value)
                    except Exception as cb_err:
                        logger.error(f"Error in Kafka consumer callback: {cb_err}")
            except asyncio.CancelledError:
                logger.info("Kafka consumer loop cancelled.")
            except Exception as e:
                logger.error("Kafka consumer error: %s", e)
            finally:
                await self.consumer.stop()

        self.consume_task = asyncio.create_task(consume_loop())

    async def wait_for_consumer(self, timeout: float = 3.0) -> bool:
        """Wait until the consumer has partitions assigned."""
        if not self.is_connected or not self.consumer:
            return False
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if self.consumer_ready:
                return True
            await asyncio.sleep(0.1)
        return False

    async def stop_consumer(self):
        if self.consume_task:
            self.consume_task.cancel()
        if self.consumer:
            await self.consumer.stop()
        if self._listener:
            self._listener.consumer_ready = False


streaming_client = KafkaStreamingClient()
