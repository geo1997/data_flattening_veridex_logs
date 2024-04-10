
import io
import sys
import os
import json
from collections import OrderedDict
import hashlib
import re


def file_hash(file_path):

    hash_md5 = ""
    hash_sha1 = ""
    hash_ha256 = ""

    if os.path.isfile(file_path):
        if os.path.getsize(file_path) > 0:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            with io.open(file_path, 'rb') as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)

            hash_md5 = str(md5.hexdigest()).lower()
            hash_sha1 = str(sha1.hexdigest()).lower()
            hash_sha256 = str(sha256.hexdigest()).lower()

    res = [
        hash_md5,
        hash_sha1,
        hash_sha256,
    ]

    md5 = None
    sha1 = None
    sha256 = None
    f = None
    sha256 = None
    data = None

    return(res)


base_paths = ["Ljunit",
            "Landroid",
            "Lcom",
            "Ldalvik",
            "Lgov",
            "Ljava",
            "Ljavax",
            "Ljdk",
            "Llibcore",
            "Lorg",
            "Lsun",
            ]




infile = r"E:\USASK\Fall Term\Research\DB\CSVs\Veridex\logs\veridex_logs_14\a6e9d7b323017dc8f3bc3502a15f030e539b9ef9.apk_veridex.txt"
#infile = "/home/user01/Desktop/Research/DB/LOG__googleplay_2023/veridex_logs_14/a6e9d7b323017dc8f3bc3502a15f030e539b9ef9.apk_veridex.txt"
outfile = "parsed_file_csv.csv"


map_caller_ids = OrderedDict()
map_callee_ids = OrderedDict()

call_seen_count = OrderedDict()


csv_header = [
    "file_location",
    "file_name",
    "file_md5",
    "file_sha1",
    "file_sha256",
    "call_number",
    "call_type",
    "restriction_list",
    "restriction_count",
    "caller_string",
    "caller_id",
    "callee_string",
    "callee_id",
    "caller_path",
    "caller_has_method",
    "caller_method_name",
    "caller_has_submethod",
    "caller_submethod_name"
]


file_parsed_call_lines = list()



# PARSE ENTIRE FILE

relative_name = infile.split("/")[-1]

# FILE HASH
hash_list = file_hash(infile)
file_md5 = hash_list[0]
file_sha1 = hash_list[1]
file_sha256 = hash_list[2]
hash_list = None

# GET LINES FROM FILE
file_lines = list()
with io.open(infile, 'r') as rif:
    for line in rif:
        xline = line.strip()
        if xline:
            file_lines.append(xline)
    xline = None
    line = None
rif = None

print("FOUND LINES --> ", len(file_lines))

call_lines = list()
for line in file_lines:
    if line.startswith("#"):
        if ("Linking" in line) or ("Reflection" in line):
            if line.endswith("use(s):"):
                call_lines.append(line)
print("FOUND LINES - CALLS --> ", len(call_lines))
file_lines = None

# MAKE STRUCTURE

#version_hf = int(infile.split("/")[-2].split("_")[-1])
version_hf = 14
# check
valid_versions = [12, 13, 14]
if not version_hf in valid_versions:
    print("VERSION HF -> ", version_hf)
    raise AssertionError("ERROR: invalid HF version")

# TEST
call_lines = [
    "#1: Reflection blocked Landroid/content/res/Resources$Theme;->rebase use(s):",
    "#2: Reflection unsupported Landroid/view/View$ListenerInfo;->mOnClickListener use(s):",
    "#3: Linking unsupported Lsun/misc/Unsafe;->compareAndSwapObject(Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z use(s):",
    "#4: Linking unsupported Lsun/misc/Unsafe;->allocateInstance(Ljava/lang/Class;)Ljava/lang/Object; use(s):",
    "#5: Linking unsupported Lsun/misc/Unsafe;->compareAndSwapObject(Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z use(s):",
    "#6: Reflection unsupported Landroid/app/ActivityThread;->currentApplication use(s):",
    "#7: Reflection unsupported Landroid/os/Trace;->TRACE_TAG_APP use(s):",
    "#8: Linking unsupported,core-platform-api Ldalvik/system/BlockGuard;->getThreadPolicy()Ldalvik/system/BlockGuard$Policy; use(s):",
    "#9: Linking unsupported Landroid/webkit/WebChromeClient;->onReachedMaxAppCacheSize(JJLandroid/webkit/WebStorage$QuotaUpdater;)V use(s):",
    "#10: Linking max-target-r Landroid/view/View$AccessibilityDelegate;->createAccessibilityNodeInfo(Landroid/view/View;)Landroid/view/accessibility/AccessibilityNodeInfo; use(s):",
    "#11: Linking max-target-p Landroid/text/StaticLayout;-><init>(Ljava/lang/CharSequence;IILandroid/text/TextPaint;ILandroid/text/Layout$Alignment;Landroid/text/TextDirectionHeuristic;FFZLandroid/text/TextUtils$TruncateAt;II)V use(s):",
    "#12: Linking max-target-o Landroid/app/IApplicationThread;->dumpMemInfo(Landroid/os/ParcelFileDescriptor;Landroid/os/Debug$MemoryInfo;ZZZZZ[Ljava/lang/String;)V use(s):",
    "#13: Linking max-target-o Landroid/app/IApplicationThread;->dumpMemInfoProto(Landroid/os/ParcelFileDescriptor;Landroid/os/Debug$MemoryInfo;ZZZZ[Ljava/lang/String;)V use(s):",
    ]

parsed_lines = len(call_lines)
for call in call_lines:

    caller_num = call.split(":")[0]
    # CHECK
    if " " in caller_num:
        print("CALLER line FIRST element -> ", caller_num)
        raise AssertionError("ERROR: first element CANNOT have spaces")

    call_number = caller_num.split("#")[1]

    call_type = call.split(": ")[1].split(" ")[0].strip()

    restriction_list = list()
    call_restrictions = call.split(" ")[2]
    if "," in call_restrictions:
        elems = call_restrictions.split(",")
        for item in elems:
            xitem = item.strip()
            if xitem:
                if not xitem in restriction_list:
                    restriction_list.append(xitem)
    else:
        restriction_list.append(call_restrictions)

    restriction_list = sorted(restriction_list)

    elems = None
    item = None
    xitem = None
    restriction_count = len(restriction_list)

    restriction_list = ",".join(restriction_list)
    call_restrictions = None

    call_string = call.split(" ")[3]

    caller = call_string.split(";->")[0]
    callee = call_string.split(";->")[1]

    # MAP CALLER TO ID
    caller_ids = len(map_caller_ids)
    if not caller in map_caller_ids:
        map_caller_ids[caller] = caller_ids + 1

    # MAP CALLEE TO ID
    callee_ids = len(map_callee_ids)
    if not callee in map_callee_ids:
        map_callee_ids[callee] = callee_ids + 1

    # MAP HOW MANY TIMES A CALL (caller OR callee) are seen across
    if not caller in call_seen_count:
        call_seen_count[caller] = 0
    call_seen_count[caller] = call_seen_count[caller] + 1

    if not callee in call_seen_count:
        call_seen_count[callee] = 0
    call_seen_count[callee] = call_seen_count[callee] + 1

    # Extracting caller (left) details

    # Split the string by the $ sign
    caller_parts = caller.split("$")

    caller_path= caller_parts[0]

    isCallerMethodExist = False
    isSubCallerMethodExist = False
    caller_method = None
    caller_sub_method = None

    if len(caller_parts) > 1:
        # Extract the part after $, including the dollar sign itself (index 1)
        caller_method = caller_parts[1]
        isCallerMethodExist = True


        if len(caller_parts) > 2:
            caller_sub_method = "$".join(caller_parts[2:])
            isSubCallerMethodExist = True

    modified_callee = callee
    for base_path in base_paths:
        modified_callee = modified_callee.replace(base_path, "|" + base_path)

    # Find all substrings that start with | and then followed by any characters until ;
    modified_callees_with_pipe = re.findall(r'\|[^;]*', modified_callee)
    base_paths_in_callee =  [path.split("/")[0][1:] for path in modified_callees_with_pipe]  # Extract base paths correctly
    output = []
    
    for i, path in enumerate(modified_callees_with_pipe, 1):
        callee_has_method = False
        callee_method_name = ""
        callee_has_submethod = False
        callee_submethod_name = ""
        base_path = ""
        
        path = path.strip('|')
        
        # Check for method
        if "$" in path:
            callee_has_method = True
            method_parts = path.split("$")
            callee_method_name = method_parts[1]
        
        # Check for submethod
        if callee_has_method and "$" in callee_method_name:
            callee_has_submethod = True
            submethod_parts = callee_method_name.split("$")
            callee_submethod_name = submethod_parts[1]
            callee_method_name = submethod_parts[0]
        
        # Output format
        output.append({
            f'callee_path_{i}': path,
            f'callee_has_method_{i}': callee_has_method,
            f'callee_method_name_{i}': callee_method_name,
            f'callee_has_submethod_{i}': callee_has_submethod,
            f'callee_submethod_name_{i}': callee_submethod_name,
            f'callee_base_path_{i}': base_paths_in_callee[i - 1]        
            })
    
    # Fill empty slots
    for j in range(len(modified_callees_with_pipe) + 1, 6):
        output.append({
            f'callee_path_{j}': "",
            f'callee_has_method_{j}': False,
            f'callee_method_name_{j}': "",
            f'callee_has_submethod_{j}': False,
            f'callee_submethod_name_{j}': "",
            f'callee_base_path_{j}': ""
        })
    
    print(output)

    total_callee_paths = 0
    callee_paths_set = set()
    base_paths_set = set()
    total_path_with_methods = 0
    callee_paths_with_methods_set = set()

    for item in output:
        for i in range(1, 6):
            path_key = f'callee_path_{i}'
            base_path_key = f'callee_base_path_{i}'
            method_key = f'callee_has_method_{i}'

            path = item.get(path_key, '')
            base_path = item.get(base_path_key, '')
            has_method = item.get(method_key, False)

            # Calculate total callee paths
            if path:
                total_callee_paths = total_callee_paths + 1
                callee_paths_set.add(path)

            # Calculate total base paths
            if base_path:
                base_paths_set.add(base_path)

            # Calculate total path with methods
            if has_method:
                total_path_with_methods = total_path_with_methods + 1
                callee_paths_with_methods_set.add(path)

    # Calculate total unique callee paths
    total_callee_unique_paths = len(callee_paths_set)

    # Calculate total unique path with methods
    total_path_with_methods_unique = len(callee_paths_with_methods_set)

    # Calculate total path with methods duplicates
    total_path_with_methods_dupes = total_path_with_methods - total_path_with_methods_unique

    # Output the results
    print("# total_callee_paths :", total_callee_paths)
    print("# total_callee_unique_paths :", total_callee_unique_paths)
    print("# callee_total_base_paths :", len(base_paths_set))
    print("# callee_total_path_with_methods :", total_path_with_methods)
    print("# callee_total_path_with_methods_unique:", total_path_with_methods_unique)
    print("# callee_total_path_with_methods_dupes:", total_path_with_methods_dupes)
    
    
    
    
    
    
    
    
    
    
    

    # RESULT
    res = [
        infile,
        relative_name,
        file_md5,
        file_sha1,
        file_sha256,
        str(call_number),
        call_type,
        restriction_list,
        str(restriction_count),
        caller,
        str(map_caller_ids[caller]),
        callee,
        str(map_callee_ids[callee]),
        caller_path,
        str(isCallerMethodExist),
        str(caller_method),
        str(isSubCallerMethodExist),
        str(caller_sub_method),

    ]

    # CHECK
    if not len(res) == len(csv_header):
        print("LEN - Result -> ", len(res))
        print("LEN - header -> ", len(csv_header))
        raise AssertionError("ERROR: csv data format MISMATCH")


    parsed_line = "|".join(res)
    #parsed_line = ",".join(res)


    file_parsed_call_lines.append(parsed_line)

    parsed_line = None
    caller = None
    callee = None
    caller_ids = None
    callee_ids = None

call = None

# CHECK
if not parsed_lines == len(file_parsed_call_lines):
    print("LINES - PARSED -> ", len(file_parsed_call_lines))
    print("LINES - PARSED -> ", parsed_lines)
    raise AssertionError("ERROR: input lines NOT equal to parsed lines")




#WRITE CSV TO DISK
# with io.open(outfile, 'w') as wof:
#     # WRITE HEADER
#     header_line = "|".join(csv_header)
#     wof.write(header_line + "\n")

#     # WRITE DATA LINES
#     for item in file_parsed_call_lines:
#         wof.write(item + "\n")
# WRITE CSV TO DISK
# with io.open(outfile, 'w', newline='') as wof:
#     # WRITE HEADER
#     header_line = ",".join(csv_header)
#     wof.write(header_line + "\n")

#     # WRITE DATA LINES
#     for item in file_parsed_call_lines:
#         wof.write(item + "\n")

wof = None
header_line = None
item = None



sys.exit()

# add caller BASE PATH
#
#
# CALLED
#
# <init>(Ljava/lang/CharSequence;IILandroid/text/TextPaint;ILandroid/text/Layout$Alignment;Landroid/text/TextDirectionHeuristic;FFZLandroid/text/TextUtils$TruncateAt;II)V use(s):",
#
#
# <init>(Ljava/lang/CharSequence;IILandroid/text/TextPaint;ILandroid/text/Layout$Alignment;Landroid/text/TextDirectionHeuristic;FFZLandroid/text/TextUtils$TruncateAt;II)V use(s):",
#
# for each string in base_path
# if string in call line
# replace string with "|string"
#
#     Landroid
# we have
#     |Landroid
#
# <init>(|Ljava/lang/CharSequence;II|Landroid/text/TextPaint;I|Landroid/text/Layout$Alignment;|Landroid/text/TextDirectionHeuristic;FFZ|Landroid/text/TextUtils$TruncateAt;II)V use(s):",
#
# the split at |
#
#
# <init>(
#     |Ljava/lang/CharSequence;II
#     |Landroid/text/TextPaint;I
#     |Landroid/text/Layout$Alignment;
#     |Landroid/text/TextDirectionHeuristic;FFZ
#     |Landroid/text/TextUtils$TruncateAt;II)V
#
# the split each piece at ;
#
# <init>(
#     |Ljava/lang/CharSequence
#     II
#     |Landroid/text/TextPaint
#     I
#     |Landroid/text/Layout$Alignment
#
#     |Landroid/text/TextDirectionHeuristic
#     FFZ
#     |Landroid/text/TextUtils$TruncateAt
#     II)V
#
# keep only if string starts with |
#
# |Ljava/lang/CharSequence
# |Landroid/text/TextPaint
# |Landroid/text/Layout$Alignment
# |Landroid/text/TextUtils$TruncateAt
# |Landroid/text/TextDirectionHeuristic
#
#
#
# total_callee_paths
# total_calee_unique_paths
# callee_total_base_paths
# callee_total_path_with_methods
# callee_total_path_with_methods_unique
# callee_total_path_with_methods_dupes





# callee_path_1                 --> Ldalvi k /syste m /DexPathList
# callee_has_method_1           --> False
# callee_method_name_1          --> ""
# callee_has_submethod_1        --> False
# callee_submethod_name_1       --> ""
# callee_base_path_1            --> ""

# callee_path_2                 --> Ldalvi k /syste m /DexPathList
# callee_has_method_2           --> False
# callee_method_name_2          --> ""
# callee_has_submethod_2        --> False
# callee_submethod_name_2       --> ""
# callee_base_path_2            --> ""

# callee_path_3                 --> Ldalvi k /syste m /DexPathList
# callee_has_method_3           --> False
# callee_method_name_3          --> ""
# callee_has_submethod_3        --> False
# callee_submethod_name_3       --> ""
# callee_base_path_3            --> ""

# callee_path_4                 --> Ldalvi k /syste m /DexPathList
# callee_has_method_4           --> False
# callee_method_name_4          --> ""
# callee_has_submethod_4        --> False
# callee_submethod_name_4       --> ""
# callee_base_path_4            --> ""

# callee_path_5                 --> Ldalvi k /syste m /DexPathList
# callee_has_method_5           --> False
# callee_method_name_5          --> ""
# callee_has_submethod_5        --> False
# callee_submethod_name_5       --> ""
# callee_base_path_5            --> ""

# callee_path_6                 --> Ldalvi k /syste m /DexPathList
# callee_has_method_6           --> False
# callee_method_name_6          --> ""
# callee_has_submethod_6        --> False
# callee_submethod_name_6       --> ""
# callee_base_path_6            --> ""





# 1: Linking unsupported Landroid/app/ActivityThread;->currentActivityThread()Landroid/app/ActivityThread; use(s):
# 2: Linking unsupported Landroid/app/ActivityThread;->getProcessName()Ljava/lang/String; use(s):
# 3: Linking unsupported Ldalvik/system/DexFile;->loadClassBinaryName(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/util/List;)Ljava/lang/Class; use(s):
# 4: Linking unsupported,core-platform-api Ldalvik/system/VMRuntime;->getRuntime()Ldalvik/system/VMRuntime; use(s):
# 5: Linking unsupported,core-platform-api Ldalvik/system/VMRuntime;->vmInstructionSet()Ljava/lang/String; use(s):
# 6: Reflection unsupported Landroid/app/PendingIntent;->getTag use(s):
# 7: Reflection unsupported Landroid/app/servertransaction/ClientTransaction;->getCallbacks use(s):
# 8: Reflection unsupported Landroid/app/servertransaction/LaunchActivityItem;->mInfo use(s):
# 9: Reflection unsupported Landroid/os/Message;->next use(s):
# 10: Reflection unsupported Landroid/os/MessageQueue;->mMessages use(s):
# 11: Reflection unsupported Landroid/os/SystemProperties;->addChangeCallback use(s):
# 12: Reflection unsupported Landroid/os/SystemProperties;->set use(s):
# 13: Reflection unsupported Landroid/os/Trace;->TRACE_TAG_APP use(s):
# 14: Reflection unsupported Landroid/os/Trace;->isTagEnabled use(s):
# 15: Reflection unsupported Landroid/os/Trace;->setAppTracingAllowed use(s):
# 16: Reflection max-target-q,core-platform-api Lcom/android/org/conscrypt/OpenSSLSocketImpl;->setUseSessionTickets use(s):
# 17: Reflection unsupported,core-platform-api Ldalvik/system/BaseDexClassLoader;->getLdLibraryPath use(s):
# 18: Reflection unsupported Ldalvik/system/BaseDexClassLoader;->pathList use(s):
# 19: Reflection blocked Ldalvik/system/BaseDexClassLoader;->sharedLibraryLoaders use(s):
# 20: Reflection unsupported Ldalvik/system/DexPathList$Element;->dexFile use(s):
# 21: Reflection unsupported Ldalvik/system/DexPathList$Element;->path use(s):
# 22: Reflection unsupported Ldalvik/system/DexPathList;->dexElements use(s):
# 23: Reflection unsupported Ljava/lang/ClassLoader;->parent use(s):





































































sys.exit()


