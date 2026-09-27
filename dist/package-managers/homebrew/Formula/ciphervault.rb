class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.20"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-aarch64-apple-darwin.tar.gz"
      sha256 "f16fa10e07e9aa58979a264dc60d8d9fe4f63a8bb7f6dc1f3b811db794ae6160"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-x86_64-apple-darwin.tar.gz"
      sha256 "4e89b3470498e66a9ab578c2233297cb9eb676205b184e5727673a1273ee940f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "22a6141bf205162b048ab070c0ab9666cb0a87dd1f36d0148054419e50c43ab6"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.20/ciphervault-v1.0.20-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "f04bd00fee0a41d74306cf8b0905b1b0712c9ed72b46b6898d7dfb8cf03eef5b"
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
