from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UploadedArtifact:
    key: str
    content_type: str
    bytes: int


class R2ArtifactUploader:
    def __init__(
        self,
        *,
        bucket: str,
        endpoint_url: str,
        access_key_id: str,
        secret_access_key: str,
        region_name: str = "auto",
        key_prefix: str = "runs",
    ) -> None:
        import boto3

        self.bucket = bucket
        self.key_prefix = key_prefix.strip("/")
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region_name,
        )

    def upload_run_artifacts(self, *, run_path: str | Path, artifact_prefix: str) -> list[UploadedArtifact]:
        base = Path(run_path)
        uploads: list[UploadedArtifact] = []
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(base).as_posix()
            key = "/".join(part for part in [self.key_prefix, artifact_prefix.strip("/"), relative] if part)
            content_type = _content_type(path)
            self.client.upload_file(
                str(path),
                self.bucket,
                key,
                ExtraArgs={"ContentType": content_type},
            )
            uploads.append(UploadedArtifact(key=key, content_type=content_type, bytes=path.stat().st_size))
        return uploads


def _content_type(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed:
        return guessed
    if path.suffix == ".md":
        return "text/markdown"
    return "application/octet-stream"

