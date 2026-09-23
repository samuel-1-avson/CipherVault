class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.13"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.13/ciphervault-v1.0.13-aarch64-apple-darwin.tar.gz"
      sha256 "5152333833eec21add8670d9542554a4fa6324b1060d4ed069c8af7c3a3aeb85"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.13/ciphervault-v1.0.13-x86_64-apple-darwin.tar.gz"
      sha256 "1d598a6cb44dd7575e0c697578503ad3b03793ee045803c349ed1c33aebb7902"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.13/ciphervault-v1.0.13-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "de34eaee135d3dcbe55f2aad8b2f6268980c68134cf8d10d67ee84e6663f3296"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.13/ciphervault-v1.0.13-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "048af65924b73f1e254723463e70fab54c98df76a3138b3678249fe8a0b8c955"
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
