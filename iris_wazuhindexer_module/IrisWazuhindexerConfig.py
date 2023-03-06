#!/usr/bin/env python3
#
#
#  IRIS wazuhindexer Source Code
#  Copyright (C) 2023 - SOCFortress
#  info@socfortress.co
#  Created by SOCFortress - 2023-03-06
#
#  License MIT

module_name = "IrisWazuhindexer"
module_description = ""
interface_version = 1.1
module_version = 1.0

pipeline_support = False
pipeline_info = {}


module_configuration = [
    {
        "param_name": "wazuhindexer_url",
        "param_human_name": "wazuhindexer URL",
        "param_description": "",
        "default": None,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_key",
        "param_human_name": "wazuhindexer key",
        "param_description": "wazuhindexer API key",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    
    {
        "param_name": "wazuhindexer_manual_hook_enabled",
        "param_human_name": "Manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "wazuhindexer_on_create_hook_enabled",
        "param_human_name": "Triggers automatically on IOC create",
        "param_description": "Set to True to automatically add a wazuhindexer insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "wazuhindexer_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a wazuhindexer insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "wazuhindexer_report_as_attribute",
        "param_human_name": "Add wazuhindexer report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, base on the wazuhindexer report. Attributes are based "
                             "on the templates of this configuration",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },# TODO: careful here, remove backslashes from \{\{ results| tojson(indent=4) \}\}
    {
        "param_name": "wazuhindexer_domain_report_template",
        "param_human_name": "Domain report template",
        "param_description": "Domain report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                   "class=\"accordion\">\n            <h3>wazuhindexer raw results</h3>\n\n           "
                   " <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r_wazuhindexer\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_raw_wazuhindexer\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_raw_wazuhindexer\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-file\"></div>\n                    </div>\n              "
                   "      <div class=\"span-title\">\n                        wazuhindexer raw "
                   "results\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_raw_wazuhindexer\" class=\"collapse\" aria-labelledby=\"drop_r_wazuhindexer\" "
                   "style=\"\">\n                    <div class=\"card-body\">\n              "
                   "          <div id='wazuhindexer_raw_ace'>\{\{ results| tojson(indent=4) \}\}</div>\n  "
                   "                  </div>\n                </div>\n            </div>\n    "
                   "    </div>\n    </div>\n</div> \n<script>\nvar wazuhindexer_in_raw = ace.edit("
                   "\"wazuhindexer_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: "
                   "30,\n});\nwazuhindexer_in_raw.setReadOnly(true);\nwazuhindexer_in_raw.setTheme("
                   "\"ace/theme/tomorrow\");\nwazuhindexer_in_raw.session.setMode("
                   "\"ace/mode/json\");\nwazuhindexer_in_raw.renderer.setShowGutter("
                   "true);\nwazuhindexer_in_raw.setOption(\"showLineNumbers\", "
                   "true);\nwazuhindexer_in_raw.setOption(\"showPrintMargin\", "
                   "false);\nwazuhindexer_in_raw.setOption(\"displayIndentGuides\", "
                   "true);\nwazuhindexer_in_raw.setOption(\"maxLines\", "
                   "\"Infinity\");\nwazuhindexer_in_raw.session.setUseWrapMode("
                   "true);\nwazuhindexer_in_raw.setOption(\"indentedSoftWrap\", "
                   "true);\nwazuhindexer_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
    
]