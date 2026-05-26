#!/usr/bin/env bash
set -u

target_name="${1:-vk-turn-proxy}"

mask_cmd() {
	local cmd="$1"
	printf '%s\n' "$cmd" | sed -E 's/(-wrap-key[ =])[^ ]+/\1<masked>/g'
}

read_cmdline() {
	local pid="$1"
	if [[ -r "/proc/$pid/cmdline" ]]; then
		tr '\0' ' ' <"/proc/$pid/cmdline" | sed 's/[[:space:]]*$//'
	fi
}

find_pids() {
	local pid cmd self_pid="$$"
	for proc in /proc/[0-9]*; do
		pid="${proc##*/}"
		[[ "$pid" == "$self_pid" ]] && continue
		cmd="$(read_cmdline "$pid")"
		[[ -z "$cmd" ]] && continue
		[[ "$cmd" == *"$target_name"* ]] || continue
		printf '%s\n' "$pid"
	done
}

print_process_report() {
	local pid="$1"
	local cmd fd_count udp_count

	if [[ ! -d "/proc/$pid" ]]; then
		printf 'PID %s: process disappeared\n' "$pid"
		return
	fi

	cmd="$(read_cmdline "$pid")"
	fd_count="$(find "/proc/$pid/fd" -maxdepth 1 -type l 2>/dev/null | wc -l)"
	udp_count="$(ss -uapn 2>/dev/null | grep -F "pid=$pid," | wc -l)"

	printf '\n== PID %s ==\n' "$pid"
	printf 'cmd: %s\n' "$(mask_cmd "$cmd")"
	printf 'fd_count: %s\n' "$fd_count"
	printf 'udp_socket_count: %s\n' "$udp_count"
	printf '\nps:\n'
	ps -o pid,ppid,etime,pcpu,pmem,nlwp -p "$pid"
	printf '\nUDP sockets:\n'
	ss -uapn 2>/dev/null | grep -F "pid=$pid," || printf '(none)\n'
}

main() {
	local pids pid count

	printf 'diagnose-vk-turn-proxy at %s\n' "$(date -Is)"
	printf 'target_name: %s\n' "$target_name"

	mapfile -t pids < <(find_pids)
	count="${#pids[@]}"

	if [[ "$count" -eq 0 ]]; then
		printf '\nNo process matching "%s" was found.\n' "$target_name"
		printf 'Try: ps aux | grep -i vk-turn-proxy\n'
		exit 1
	fi

	printf 'matched_processes: %s\n' "$count"
	for pid in "${pids[@]}"; do
		print_process_report "$pid"
	done
}

main "$@"
