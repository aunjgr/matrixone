import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('cutover_verify',Path(__file__).resolve().parents[1]/'verify.py')
verify=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)

    def test_corrupted_artifact_is_rejected(self):
        (self.root/'data').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'corrupt'):
            verify.check_files(self.root,{'data':hashlib.sha256(b'original').hexdigest()})

    def test_missing_artifact_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'missing'):
            verify.check_files(self.root,{'missing':'0'*64})

    def test_missing_profile_chunk_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'missing'):
            verify.join_chunks(self.root,{'chunks':['gone'],'sha256':'0'*64},self.root/'joined')

    def test_changed_profile_chunks_are_rejected(self):
        (self.root/'part').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'checksum'):
            verify.join_chunks(self.root,{'chunks':['part'],'sha256':'0'*64},self.root/'joined')

    def test_archive_cannot_escape_extraction_directory(self):
        archive=self.root/'archive.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:
            member=tarfile.TarInfo('../escape');member.size=1
            tar.addfile(member,io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError,'path'):
            verify.extract(archive,self.root/'extracted')
        self.assertFalse((self.root/'escape').exists())

    def test_archive_symlink_is_rejected(self):
        archive=self.root/'archive.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:
            member=tarfile.TarInfo('link');member.type=tarfile.SYMTYPE;member.linkname='/tmp'
            tar.addfile(member)
        with self.assertRaisesRegex(ValueError,'nonregular'):
            verify.extract(archive,self.root/'extracted')


if __name__=='__main__':unittest.main()
