import importlib.util,json,os,tempfile,unittest
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/'scripts/database-onboarding.py'
class RunnerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  spec=importlib.util.spec_from_file_location('runner',SCRIPT);cls.r=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.r)
 def request(self,**extra):
  return {'action':'CHECK','instanceId':'5ca86e48-4413-40b0-8704-b885f3a2f18f','assetId':'9aa003bf-5c2f-49ce-aec6-288a32baaed1','engine':'postgresql','selfAuditSafe':False,'target':{'deployment':'HOST','port':5432,'database':'selfguard'},**extra}
 def test_input_rejects_command_and_target_overrides(self):
  for field in [{'action':'RESTART'},{'instanceId':'../../root'},{'target':{'deployment':'DOCKER','container':'x;reboot','port':5432,'database':'selfguard'}},{'target':{'deployment':'HOST','port':5432,'database':'host=outside dbname=x'}}]:
   with self.assertRaises(self.r.Failure):self.r.validate(self.request(**field))
 def test_collector_off_never_enables_sql(self):
  settings={'logging_collector':'off','log_min_duration_statement':'-1'}
  self.assertEqual(self.r.activation_state(settings,'INSTALL'),('WAITING_RESTART','COLLECTOR_OFF'))
  self.assertEqual(self.r.activation_state(settings,'CHECK'),('CHECKED','COLLECTOR_OFF'))
 def test_path_rejects_symlink_at_every_component(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t).resolve();(p/'real').mkdir();(p/'alias').symlink_to(p/'real',target_is_directory=True)
   with self.assertRaises(self.r.Failure):self.r.safe_path(p/'alias'/'future',allow_missing=True)
 def test_retention_only_owned_names_and_early_seven_day_cutoff(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t).resolve();(p/'.selfguard-owner').write_text('owned-instance')
   for name in ['selfguard-20200101000000.csv','business.csv','selfguard-29990101000000.csv']:(p/name).write_text('synthetic')
   result=self.r.expire_logs(p,'owned-instance',now=1794456000)
   self.assertFalse((p/'selfguard-20200101000000.csv').exists());self.assertTrue((p/'business.csv').exists());self.assertTrue((p/'selfguard-29990101000000.csv').exists());self.assertEqual(result['expiredFiles'],1)
 def test_expiry_rejects_unowned_directory(self):
  with tempfile.TemporaryDirectory() as t:
   with self.assertRaises(self.r.Failure):self.r.expire_logs(Path(t).resolve(),'other',now=1794456000)
 def test_installed_retention_program_is_executable(self):
  compile(self.r.RETENTION_SCRIPT,"installed-retention.py","exec")
 def test_units_only_start_owned_collector_and_never_restart_database(self):
  units=self.r.service_units('5ca86e48-4413-40b0-8704-b885f3a2f18f','/srv/postgres/logs')
  text='\n'.join(units.values())
  self.assertIn('--database-monitor',text);self.assertIn('ProtectSystem=strict',text);self.assertNotIn('systemctl restart postgresql',text);self.assertNotIn('docker restart',text)
  self.assertIn('OnCalendar=',text)
if __name__=='__main__':unittest.main()
