class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.7-beta.10"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.7-beta.10/ciphervault-v1.0.7-beta.10-aarch64-apple-darwin.tar.gz"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.7-beta.10/ciphervault-v1.0.7-beta.10-x86_64-apple-darwin.tar.gz"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.7-beta.10/ciphervault-v1.0.7-beta.10-aarch64-unknown-linux-gnu.tar.gz"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.7-beta.10/ciphervault-v1.0.7-beta.10-x86_64-unknown-linux-gnu.tar.gz"
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
