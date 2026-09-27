class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.20"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-aarch64-apple-darwin.tar.gz"
      sha256 "38f8f59a32acc9feac32612c49c72cb239cb3df49be93584029f7de7a6054b38"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-x86_64-apple-darwin.tar.gz"
      sha256 "45ec1c4a7338a3f9df739e66cdb5da372bf95ccb499d9dd57432ab32485b2a14"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "3995e01bfc32128afc7c8a183aab093a7081915888b5c08e75eb5c40ad8cbb83"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "514b0367aee969cbc98a8d69cdc9081cab61a5739ba203c4feae01532eaf07d7"
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
