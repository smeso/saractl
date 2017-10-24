"""
    saractl - S.A.R.A.'s userspace utilities.
    Copyright (C) 2017  Salvatore Mesoraca <s.mesoraca16@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


def c_array(data):
    s = []
    for i, b in enumerate(data, 1):
        if i % 8:
            s.append('0x{:02X}, '.format(b))
        else:
            s.append('0x{:02X},\n\t\t\t\t'.format(b))
    s[-1] = s[-1].strip('\n\t, ')
    return ''.join(s)


SH_TEMPLATE = """#!/bin/sh
SECFS="{sysfs_path}"

WXPROT="{wxprot}"
WXPROTN="{wxprot_noemutramp}"

if [ -f "${{SECFS}}/sara/wxprot/emutramp_available" ] && \\
   [ "`cat "${{SECFS}}/sara/wxprot/emutramp_available"`" -eq 1 ]; then
    echo "${{WXPROT}}" | base64 -d > "${{SECFS}}/sara/wxprot/.load"
else
    echo "${{WXPROTN}}" | base64 -d > "${{SECFS}}/sara/wxprot/.load"
fi

echo "{wxprot_xattr_enabled}" > "${{SECFS}}/sara/wxprot/xattr_enabled"
echo "{wxprot_xattr_user_allowed}" > "${{SECFS}}/sara/wxprot/xattr_user_allowed"
echo "{wxprot_enabled}" > "${{SECFS}}/sara/wxprot/enabled"
echo "{sara_enabled}" > "${{SECFS}}/sara/main/enabled"
#echo "{sara_locked}" > "${{SECFS}}/sara/main/locked"

exit 0
"""

C_TEMPLATE = """#include <stdio.h>

#define SECFS "{sysfs_path}"

unsigned char WXPROT[] =\t{{{wxprot}}};
unsigned char WXPROTN[] =\t{{{wxprot_noemutramp}}};

int main()
{{
    FILE *f;
    char buf;

    f = fopen(SECFS "/sara/wxprot/emutramp_available", "r");
    if (f != NULL) {{
        fread(&buf, 1, 1, f);
        fclose(f);
        f = fopen(SECFS "/sara/wxprot/.load", "wb");
        if (f != NULL) {{
            if (buf == '1')
                fwrite(WXPROT, sizeof(WXPROT), 1, f);
            else
                fwrite(WXPROTN, sizeof(WXPROTN), 1, f);
            fclose(f);
        }}
    }}
    f = fopen(SECFS "/sara/wxprot/xattr_enabled", "w");
    if (f != NULL) {{
        fwrite("{wxprot_xattr_enabled}", 1, 1, f);
        fclose(f);
    }}
    f = fopen(SECFS "/sara/wxprot/xattr_user_allowed", "w");
    if (f != NULL) {{
        fwrite("{wxprot_xattr_user_allowed}", 1, 1, f);
        fclose(f);
    }}
    f = fopen(SECFS "/sara/wxprot/enabled", "w");
    if (f != NULL) {{
        fwrite("{wxprot_enabled}", 1, 1, f);
        fclose(f);
    }}
    f = fopen(SECFS "/sara/main/enabled", "w");
    if (f != NULL) {{
        fwrite("{sara_enabled}", 1, 1, f);
        fclose(f);
    }}
    //f = fopen(SECFS "/sara/main/locked", "w");
    //if (f != NULL) {{
    //    fwrite("{sara_locked}", 1, 1, f);
    //    fclose(f);
    //}}
    return 0;
}}
"""
