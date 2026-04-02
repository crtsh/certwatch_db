# Aggregate endpoint uptime by LOG_URL and compute the minimum uptime across all endpoints.
# Input: CSV with fields LOG_URL, ENDPOINT, UPTIME
# Output: Space-delimited with fields LOG_URL, UPTIME_PERCENTAGE (minimum)

BEGIN {
	FS = ","
}

# Skip CSV header row
NR == 1 {
	next
}

# Process data rows: extract URL and uptime, force numeric comparison
{
	url = $1
	uptime = $3 + 0  # Force numeric conversion to avoid lexicographic comparison
	if (!(url in mins) || uptime < mins[url]) {
		mins[url] = uptime
	}
}

# Emit header and all aggregated minima
END {
	print "LOG_URL UPTIME_PERCENTAGE"
	for (url in mins) {
		printf "%s %.4f\n", url, mins[url]
	}
}
