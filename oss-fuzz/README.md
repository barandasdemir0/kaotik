# OSS-Fuzz başvurusu

Bu klasör, kaotik'i [google/oss-fuzz](https://github.com/google/oss-fuzz)'a eklemek için hazır dosyaları içerir.

1. `project.yaml` içindeki `primary_contact` alanına Google hesabına bağlı gerçek e-postanı yaz (`TODO@example.com` yerine).
2. google/oss-fuzz'u fork'la, bu üç dosyayı (`project.yaml`, `Dockerfile`, `build.sh`) `projects/kaotik/` altına kopyala.
3. Yerelde dene: `python3 infra/helper.py build_fuzzers kaotik` ve `python3 infra/helper.py check_build kaotik`.
4. google/oss-fuzz'a PR aç ("Add kaotik").

Not: OSS-Fuzz yalnızca aktif bakımı yapılan ve gerçekten kullanılan (ya da kritik altyapıda yer alan)
açık kaynak projeleri kabul eder; başvuru reddedilebilir. O zamana kadar repodaki
ClusterFuzzLite (`.clusterfuzzlite/`, `cflite_*.yml`) sürekli fuzzing sağlar.
