FROM ubuntu:latest
ENV USER=deploy
ENV PASSWD=deploy
ENV WORKDIR=IOTSSE
ENV TZ=Australia/Melbourne

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update \
    && apt install -y ssh openssh-server build-essential \
      gcc g++ gdb gdbserver cmake flex bison \
      rsync \
      libssl-dev \
      libgmp-dev \
      sudo git \
    && apt clean \
    && wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar xf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 && ./configure && make && make install \
    && cd .. \
    && rm -rf pbc-0.5.14

RUN useradd -m ${USER} && yes ${PASSWD} | passwd ${USER}

RUN echo ${USER}' ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN chmod 644 /etc/sudoers

CMD ["/usr/sbin/sshd", "-D"]

USER ${USER}
RUN mkdir -p /home/${USER}/${WORKDIR}/
ENV LC_ALL C.UTF-8