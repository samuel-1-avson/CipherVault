class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.25"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-aarch64-apple-darwin.tar.gz"
      sha256 "4c1d813d825183f661ad25cc5687c39158e69872bedc2dd9c0136e35ed3f404e"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-x86_64-apple-darwin.tar.gz"
      sha256 "5df066def9de8aa1c33f8ca68d1e45588c1fcdc6f440f0819f18b0bfba880f92"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1d869b071920edd676f644733cb429686ef5bc9ba5a83be22cac0a0cd7f8efb4"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3f07de25751a93e36e9db74257f25b1eef1ffcf35e5df4f942fa1d79beaa52c6"
    end
  end

  def install
    bin.install "bin/ciphervault"
    bin.install "bin/ciphervault-operator"
    bin.install "bin/ciphervault-agent"
    bin.install "bin/ciphervault-maintenance"

    if Dir.exist?("config")
      (etc/"ciphervault").install Dir["config/*"]
    end
  end

  def caveats
    <<~EOS
      Quick Start:
        ciphervault init
        ciphervault track .env
        ciphervault push -m "Initial commit"
        ciphervault diff
        ciphervault run -- npm start
        ciphervault peers
    EOS
  end

  test do
    assert_match "Decentralized, encrypted version control", shell_output("#{bin}/ciphervault --help")
  end
end
