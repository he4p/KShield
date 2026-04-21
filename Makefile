.PHONY: manager bpf agent deploy-deps

manager:
	bash scripts/start_manager.sh

bpf:
	bash agent/build_bpf.sh

agent:
	bash scripts/build_agent.sh

deploy-deps:
	sudo pacman -S --noconfirm python-paramiko
