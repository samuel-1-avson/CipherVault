class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.38"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.38/ciphervault-v1.0.38-aarch64-apple-darwin.tar.gz"
      sha256 "515b39070b444701b31113d3cb51c39089431c1297bd819d58a08f1a9bb0c630"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.38/ciphervault-v1.0.38-x86_64-apple-darwin.tar.gz"
      sha256 "0466283a4b348135a70a63bee861f4f86722c138fd3626083a24050c6dc5d555"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.38/ciphervault-v1.0.38-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5d24140a71a6f03e1741ce887a3def6b143faa7c9fe46a89a2a4f2bb76bc089c"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.38/ciphervault-v1.0.38-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "f24e7d6661f12ac54f5c594a58ca6dbf7371c533796226de2f110edad52d0db3"
    end
  end

  def install
    bin.install "bin/ciphervault"
    bin.install "bin/cv"
    bin.install "bin/ciphervault-operator"
    bin.install "bin/ciphervault-agent"
    bin.install "bin/ciphervault-maintenance"

    if Dir.exist?("config")
      (etc/"ciphervault").install Dir["config/*"]
    end
  end

  def caveats
    <<~EOS
      Quick Start (cv and ciphervault are the same tool):
        cv init
        cv track .env
        cv push -m "Initial commit"
        cv diff
        cv run -- npm start
        cv peers
    EOS
  end

  test do
    assert_match "Decentralized, encrypted version control", shell_output("#{bin}/ciphervault --help")
    assert_match "cv node setup", shell_output("#{bin}/cv --help")
  end
end
