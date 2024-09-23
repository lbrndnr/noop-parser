# no-op parser

This is a small example that demonstrates a bug in the linux kernel. The problem arises when a BPF program of type `BPF_SK_SKB_STREAM_VERDICT` does not redirect `__sk_buff`, but instead just returns `SK_PASS`.

## Usage
This will make your system unresponsive until it's unusable. So make sure to run this in a VM.
First, load the BPF programs as follows
```bash
./load.sh
```

Next, open up a socket using netcat
```bash
nc -l -p 8000
```

Finally, connect to it and send some data.
```bash
nc 127.0.0.1 8000
hello
hi
```

Alternatively, you can compile the BPF program with the `REDIRECT` flag. This causes the stream verdict to call `bpf_sk_redirect_hash`.
That should avoid the kernel from deadlocking, but if you make multiple requests using netcat, you'll notice that not all of them make it through immediately.
```bash
./unload.sh
./load.sh -DREDIRECT
```