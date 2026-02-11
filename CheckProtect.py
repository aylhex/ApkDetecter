# -*- coding: utf-8 -*-
__author__ = 'Andy'

import json
import os
from androguard.core.apk import APK

class CheckProtect:
    def __init__(self, apk_obj):
        """
        :param apk_obj: androguard.core.apk.APK object
        """
        self.apk = apk_obj
        self.signatures = []
        self._load_signatures()

    def _load_signatures(self):
        """
        Load signatures from Resources/signatures.json
        """
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            json_path = os.path.join(base_dir, 'Resources', 'signatures.json')
            
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.signatures = data.get('signatures', [])
            else:
                # Fallback if file not found (though it should be there)
                print(f"Warning: Signature file not found at {json_path}")
        except Exception as e:
            print(f"Error loading signatures: {e}")

    def check_protectflag(self):
        detected_protectors = set()
        files = self.apk.get_files()
        
        # Pre-process files for faster matching
        # file_set: just filenames (e.g., "libjiagu.so")
        file_set = set()
        # path_set: full paths (e.g., "assets/libjiagu.so")
        path_set = set(files)
        
        for f in files:
            # Extract basename
            if '/' in f:
                basename = f.split('/')[-1]
            else:
                basename = f
            file_set.add(basename)

        for signature in self.signatures:
            name = signature['name']
            rules = signature.get('rules', [])
            
            match_found = False
            for rule in rules:
                rule_type = rule.get('type', 'file')
                
                if rule_type == 'combined':
                    # All conditions must be met
                    conditions = rule.get('conditions', [])
                    all_conditions_met = True
                    for cond in conditions:
                        if not self._check_rule(cond, file_set, path_set):
                            all_conditions_met = False
                            break
                    if all_conditions_met:
                        match_found = True
                        break
                else:
                    # Single rule
                    if self._check_rule(rule, file_set, path_set):
                        match_found = True
                        break
            
            if match_found:
                detected_protectors.add(name)

        if detected_protectors:
            # Format: "该APK已加固=>360加固 腾讯加固"
            return "该APK已加固=>" + " ".join(sorted(detected_protectors))
        
        return "该APK未加密"

    def _check_rule(self, rule, file_set, path_set):
        rule_type = rule.get('type', 'file')
        pattern = rule.get('pattern', '')
        match_mode = rule.get('match', 'exact') # exact, startswith, endswith, contains

        target_set = file_set if rule_type == 'file' else path_set

        # Optimization for exact match on file set
        if rule_type == 'file' and match_mode == 'exact':
            return pattern in target_set

        # For other cases, iterate
        for item in target_set:
            if match_mode == 'exact':
                if item == pattern: return True
            elif match_mode == 'startswith':
                if item.startswith(pattern): return True
            elif match_mode == 'endswith':
                if item.endswith(pattern): return True
            elif match_mode == 'contains':
                if pattern in item: return True
        
        return False
