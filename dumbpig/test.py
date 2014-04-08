import dumbpig

dp = dumbpig.RuleChecker()
print dp.get_dumbpig_version()
#dp.set_rule_file('/Users/jester/Documents/et_rules/emerging-voip.rules')
dp.set_rule_file('/Users/jester/Downloads/dumbpig-0.10/bad.rules')
dp.test_rule_file()
#print dp.print_output()
dp.process_output()