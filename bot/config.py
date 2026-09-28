import os
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    bot_token: str
    admin_ids: Union[str, List[int]]

    vpn_container_name: str = "amnezia-awg2"
    server_host: str = ""
    server_port: int = 0
    wg_interface: str = ""
    client_ip_subnet: str = "10.8.1.0/24"
    client_dns: str = "1.1.1.1, 1.0.0.1"
    stats_poll_interval: int = 300
    db_path: str = "/app/data/bot.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("vpn_container_name", "server_host", "wg_interface", mode="before")
    @classmethod
    def strip_quotes(cls, v):
        if isinstance(v, str):
            return v.strip("'\" \t")
        return v

    @field_validator("server_port", mode="before")
    @classmethod
    def parse_server_port(cls, v):
        if v is None or v == "":
            return 0
        return int(v)

    @field_validator("stats_poll_interval", mode="before")
    @classmethod
    def parse_stats_poll_interval(cls, v):
        if v is None or v == "":
            return 300
        return int(v)

    @field_validator("admin_ids", mode="before")
    @classmethod
    def parse_admin_ids(cls, v):
        if isinstance(v, list):
            return [int(x) for x in v]
        if isinstance(v, (int, str)):
            if isinstance(v, int):
                return [v]
            parts = [p.strip() for p in v.split(",") if p.strip()]
            return [int(p) for p in parts]
        return []


settings = Settings()
