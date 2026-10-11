//! 文件写入工具

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// 原子写入文件：先写同目录临时文件并 fsync，再 rename 覆盖目标文件
///
/// 写入过程中进程崩溃或断电时，目标文件要么保持旧内容，要么是完整的新内容，
/// 不会出现被截断的半截文件。
pub fn write_atomic(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "目标路径缺少文件名"))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let tmp_path = path.with_file_name(tmp_name);

    let result = (|| {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(contents.as_ref())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// 将无法解析的文件复制为 `<name>.corrupt-<时间戳>` 备份，返回备份路径（失败返回 None）
pub fn backup_corrupt_file(path: impl AsRef<Path>) -> Option<std::path::PathBuf> {
    let path = path.as_ref();
    let mut backup_name = path.file_name()?.to_os_string();
    backup_name.push(format!(".corrupt-{}", chrono::Utc::now().format("%Y%m%d%H%M%S")));
    let backup = path.with_file_name(backup_name);
    fs::copy(path, &backup).ok()?;
    Some(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_atomic_replaces_content_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("kiro-fs-util-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.json");

        write_atomic(&path, "first").unwrap();
        write_atomic(&path, "second").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1, "临时文件应已被 rename 或清理");

        let _ = fs::remove_dir_all(&dir);
    }
}
