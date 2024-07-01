FROM archlinux:latest
RUN pacman -Sy base-devel go llvm clang linux-headers byobu ncurses --noconfirm
ADD . /app/
WORKDIR /app
RUN make clean all
ENTRYPOINT /app/docker-entrypoint.sh

