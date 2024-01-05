FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    curl\
    python3 \
    python3-pip\
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

RUN curl -OL https://go.dev/dl/go1.21.0.linux-amd64.tar.gz \
    && tar -xvf go1.21.0.linux-amd64.tar.gz -C /usr/local \
    && rm go1.21.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
# Set the working directory in the container
WORKDIR /app

# Clone & install kube-score
RUN KUBESCORE_VERSION="v1.5.0" \
  && KUBESCORE_TARBALL_URL="https://github.com/zegl/kube-score/releases/download/${KUBESCORE_VERSION}/kube-score_${KUBESCORE_VERSION#v}_linux_amd64.tar.gz"  \
  && curl -L -o kube-score.tar.gz "$KUBESCORE_TARBALL_URL" \
  && tar -xvzf kube-score.tar.gz -C /usr/local/bin/ \
  && chmod +x /usr/local/bin/kube-score

# Clone & install kubesec
WORKDIR /app/kubesec
RUN git clone https://github.com/controlplaneio/kubesec.git .
RUN go build -o /usr/local/bin/kubesec .

# Clone & install kubeaudit
WORKDIR /app/kubeaudit
RUN KUBEAUDIT_VERSION="v0.11.5" \
        && KUBEAUDIT_TARBALL_URL="https://github.com/Shopify/kubeaudit/releases/download/$KUBEAUDIT_VERSION/kubeaudit_${KUBEAUDIT_VERSION#v}_linux_amd64.tar.gz" \
        && curl -L -o kubeaudit.tar.gz "$KUBEAUDIT_TARBALL_URL" \
        && tar -xvzf kubeaudit.tar.gz -C /usr/local/bin/ \
        && chmod +x /usr/local/bin/kubeaudit

# Clone & install datree
WORKDIR /app/datree
RUN git clone https://github.com/datreeio/datree.git .
RUN go build -o /usr/local/bin/datree .

# Clone & install kube-linter
WORKDIR /app/kubelinter
RUN git clone https://github.com/stackrox/kube-linter.git .
RUN make build
RUN mv .gobin/kube-linter /usr/local/bin/kube-linter

# Clone & install kubescape
WORKDIR /app/kubescape
RUN git clone https://github.com/kubescape/kubescape.git .
RUN go build -o /usr/local/bin/kubescape .

WORKDIR /app

COPY . .

# Install Python dependencies
RUN pip3 install -r requirements.txt

RUN datree config set offline local
# Set the command to start the Python web server
CMD ["python3", "/app/app.py"]

ENV OPENAI_API_KEY="sk-"