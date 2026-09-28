ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# The scanner binary is mounted read-only at run time. These local tools give
# the crAPI pilot its basic HTTP, API and database checks without Docker access.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl dnsutils nmap sqlmap gobuster \
    && rm -rf /var/lib/apt/lists/*
