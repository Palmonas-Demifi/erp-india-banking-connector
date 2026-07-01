import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields


def execute():
	create_custom_fields(
		{
			"Payment Order": [
				{
					"fieldname": "icici_otp_unique_id",
					"label": "ICICI OTP Unique ID",
					"fieldtype": "Data",
					"hidden": 1,
					"read_only": 1,
					"no_copy": 1,
					"insert_after": "file_sequence_number",
				}
			]
		}
	)
