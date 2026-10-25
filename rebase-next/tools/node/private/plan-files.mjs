import { link, open, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

/** Private write-once publication primitive. `files` is a narrow fault-injection seam. */
export async function persistWriteOnce(destination, data, files = {}) {
  const openFile = files.openFile ?? open;
  const linkFile = files.linkFile ?? link;
  const unlinkFile = files.unlinkFile ?? unlink;
  const target = path.resolve(destination);
  const directory = path.dirname(target);
  const temporary = path.join(directory, `.rebase-plan-${randomUUID()}.tmp`);
  let handle;
  let published = false;
  let failure;
  try {
    handle = await openFile(temporary, 'wx', 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await linkFile(temporary, target);
    published = true;
    const dirHandle = await openFile(directory, 'r');
    try { await dirHandle.sync(); }
    finally { await dirHandle.close(); }
  } catch (cause) {
    if (published) {
      failure = new Error('Plan was published, but directory durability could not be confirmed; retain the target and reconcile rather than deleting or retrying', { cause });
      failure.name = 'ClientError';
      failure.code = 'plan_durability_unknown';
      failure.path = target;
      failure.published = true;
    } else {
      failure = cause;
    }
  }
  try {
    await handle?.close();
  } catch {
    // A failed close must not replace the publication result or primary error.
  }
  try {
    await unlinkFile(temporary);
  } catch (cause) {
    if (cause.code !== 'ENOENT' && !failure) {
      failure = new Error('Plan was published, but temporary-file cleanup failed; retain the target and remove the temporary file only after reconciliation', { cause });
      failure.name = 'ClientError';
      failure.code = 'plan_cleanup_failed';
      failure.path = target;
      failure.published = published;
    }
  }
  if (failure) throw failure;
}
