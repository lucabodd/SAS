FROM kalilinux/kali-rolling

# Metadata params
ARG BUILD_DATE
ARG VERSION
ARG VCS_URL
ARG VCS_REF

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url=$VCS_URL \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.version=$VERSION \
      org.label-schema.name='Kali Linux' \
      org.label-schema.description='Official Kali Linux docker image' \
      org.label-schema.usage='https://www.kali.org/news/official-kali-linux-docker-images/' \
      org.label-schema.url='https://www.kali.org/' \
      org.label-schema.vendor='Offensive Security' \
      org.label-schema.schema-version='1.0' \
      org.label-schema.docker.cmd='docker run --rm kalilinux/kali-rolling' \
      org.label-schema.docker.cmd.devel='docker run --rm -ti kalilinux/kali-rolling' \
      org.label-schema.docker.debug='docker logs $CONTAINER' \
      io.github.offensive-security.docker.dockerfile="Dockerfile" \
      io.github.offensive-security.license="GPLv3" \
      MAINTAINER="Santiago Figueroa <sfigueroa@ceit.es>"

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN set -x \
    && apt-get -yqq update \
    && apt-get -y install --no-install-recommends \
        metasploit-framework \
        nmap \
        hydra \
        sqlmap \
        telnet \
        openssh-client \
        dnsutils \
        yersinia \
        ettercap-text-only \
        sslscan \
        snmp \
        nano \
        dsniff \
        dnschef \
        fping \
        hping3 \
        tshark \
        python3-scapy \
        net-tools \
        iputils-ping \
        iproute2 \
        thc-ipv6 \
        tcpdump \
        sudo \
        nikto \
        curl \
        netcat-openbsd \
        git \
        ffuf \
        python3-paramiko \
        python3-pexpect \
        python3-psycopg2 \
        python3-pip \
        python2 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install pip2
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py \
    && python2 get-pip.py \
    && rm get-pip.py

# Set environment variable to prevent git from prompting for credentials
ENV GIT_TERMINAL_PROMPT=0

# Download additional Nmap script
RUN wget -P /usr/share/nmap/scripts/ http://nmap.org/svn/scripts/targets-ipv6-multicast-slaac.nse

# Clone required tools into /opt
RUN mkdir -p /opt \
    && git clone --depth 1 https://github.com/gkbrk/slowloris.git /opt/slowloris \
    && git clone --depth 1 https://github.com/jseidl/GoldenEye.git /opt/GoldenEye \
    && git clone --depth 1 https://github.com/lanjelot/patator.git /opt/patator \
    && git clone --depth 1 https://github.com/lucabodd/SAS.git /opt/SAS
# Download Python 3 Heartbleed script
RUN git clone --depth 1 https://github.com/mpgn/heartbleed-PoC.git /opt/HeartBleed \
    && chmod +x /opt/HeartBleed/heartbleed-exploit.py

# Download specific SecLists files
RUN mkdir -p /opt/SecLists/Passwords/Common-Credentials \
    /opt/SecLists/Passwords \
    /opt/SecLists/Discovery/Web-Content \
    /opt/SecLists/Fuzzing/LFI \
    /opt/SecLists/Fuzzing/XSS/robot-friendly \
    /opt/SecLists/Usernames \
    && wget -O /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
    && wget -O /opt/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000000.txt \
    && wget -O /opt/SecLists/Passwords/xato-net-10-million-passwords-100.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-100.txt \
    && wget -O /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt \
    && wget -O /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
    && wget -O /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt \
    && wget -O /opt/SecLists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
    && wget -O /opt/SecLists/Usernames/top-usernames-shortlist.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt

# Install Python packages
RUN pip3 install --no-cache-dir \
        vncdotool \
        mysql-connector-python \
    && pip3 install --no-cache-dir -r /opt/patator/requirements.txt \
    && pip3 install --no-cache-dir -r /opt/slowloris/requirements.txt \
    && pip3 install --no-cache-dir -r /opt/HeartBleed/requirements.txt \
    || true


# Ensure the script is executable
RUN chmod +x /opt/SAS/*.sh

# Add /opt/SAS to PATH
ENV PATH="/opt/SAS:${PATH}"

CMD ["bash"]