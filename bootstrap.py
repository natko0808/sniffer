'''
@ASSESSME.USERID: YOUR_GROUP_NAME
@ASSESSME.AUTHOR: Your Name - yourRIT, Teammate Name - teammateRIT
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

from pathlib import Path
import sys



LOCAL_DEPENDENCY_DIR = Path(__file__).resolve().parent / ".deps"

if LOCAL_DEPENDENCY_DIR.exists():
    dependency_path = str(LOCAL_DEPENDENCY_DIR)
    if dependency_path not in sys.path:
        sys.path.insert(0, dependency_path)

