#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

DEFAULT_REPO = "MaziyarPanahi/Qwen3-8B-GGUF"
DEFAULT_FILENAME = "Qwen3-8B.Q4_K_M.gguf"


def main():
    parser = argparse.ArgumentParser(description="Download a local GGUF model for llama-cpp-python")
    parser.add_argument("--repo-id", default=os.getenv("LOCAL_LLM_HF_REPO_ID", DEFAULT_REPO))
    parser.add_argument("--filename", default=os.getenv("LOCAL_LLM_HF_FILENAME", DEFAULT_FILENAME))
    parser.add_argument("--target-dir", default=os.getenv("LOCAL_LLM_TARGET_DIR", "models"))
    parser.add_argument("--token", default=os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_HUB_TOKEN"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--print-path", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    expected_path = target_dir / args.filename

    if args.print_path:
        print(str(expected_path))
        return

    if expected_path.exists() and not args.force:
        print(f"Model already present: {expected_path}")
        return

    if args.dry_run:
        print(f"Would download {args.repo_id}:{args.filename} -> {expected_path}")
        return

    from huggingface_hub import hf_hub_download

    downloaded = hf_hub_download(
        repo_id=args.repo_id,
        filename=args.filename,
        token=args.token,
        local_dir=str(target_dir),
        local_dir_use_symlinks=False,
        resume_download=True,
    )
    print(downloaded)


if __name__ == "__main__":
    main()
