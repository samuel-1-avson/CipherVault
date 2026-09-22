class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.8"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.8/ciphervault-v1.0.8-aarch64-apple-darwin.tar.gz"
      sha256 "089e44453dcecda48b0230bb9878e00325be8bef22cd8789015089575875b782"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.8/ciphervault-v1.0.8-x86_64-apple-darwin.tar.gz"
      sha256 "a22cd9fc7420bf2caed056d8d8079e4e442d6edb47c46fcb3e76e03349c2e98e"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.8/ciphervault-v1.0.8-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "30f7ce7bb11fd43692b1fb969acfa0d01ddf2414a5449c5c07b7650690ea2464"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.8/ciphervault-v1.0.8-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "edbf20c6e77eb897c35ef1f2957d5f626f0297b9106aa5a8d67c7a410fd2ab98"
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
