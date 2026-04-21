.PHONY: manager bpf agent deploy-deps

manager:
	bash scripts/start_manager.sh

bpf:
	bash agent/build_bpf.sh

agent:
	bash scripts/build_agent.sh

deploy-deps:
	printf 'hitler\n' | sudo -S pacman -S --noconfirm python-paramiko
