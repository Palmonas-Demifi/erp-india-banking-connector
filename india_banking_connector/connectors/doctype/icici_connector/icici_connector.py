# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import re
import secrets
from base64 import b64decode, b64encode

import frappe
import requests
from Crypto.Cipher import AES, PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from frappe import _
from frappe.utils import cstr, flt, getdate, nowdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class ICICIConnector(BankConnector):
	bank = "ICICI Bank"
	ICICI_OTP_UNIQUE_ID_FIELD = "icici_otp_unique_id"
	ICICI_SUMMARY_UNIQUE_ID_FIELD = "icici_unique_id"

	AES_KEY = "1234567887654321".encode("utf-8")
	IV = "0000000000000000".encode("utf-8")
	HYBRID_ENCRYPTION_METHODS = {
		"generate_otp",
		"make_payment",
		"payment_status",
		"bank_balance",
		"bank_statement",
	}

	__all__ = ["initiate_payment", "get_payment_status"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	@property
	def urls(self):
		return super().urls

	def headers(self, mode_of_transfer=None, params=None):
		return {
			"Accept": "*/*",
			"Content-Type": "application/Json",
			"apikey": self.client_key,
		}

	def post_request(self, url, headers, payload):
		session = requests.Session()
		session.headers.clear()
		request = requests.Request("POST", url, headers=headers, data=payload)
		prepared_request = session.prepare_request(request)
		for header in ("User-Agent", "Accept-Encoding", "Connection", "Content-Length"):
			prepared_request.headers.pop(header, None)

		return session.send(prepared_request)

	@frappe.whitelist()
	def register(self):
		self.bulk_transaction = False
		self.update_client_details("register")
		url = self.urls.register
		headers = self.headers()
		payload = self.get_encrypted_payload(method="register")

		response = self.post_request(url, headers=headers, payload=payload)

		log_id = create_api_log(
			response,
			action="Register",
			account_config=self.get_account_config("register"),
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			connector=self,
		)

		res = self.get_decrypted_response(response, method="register", log_id=log_id)
		if res.status == "success":
			self.db_set("registration_status", "Registered")
		frappe.msgprint(res.message or _("Registration Failed"))

	@frappe.whitelist()
	def registration_inquiry(self):
		self.bulk_transaction = False
		self.update_client_details("registration_status")
		url = self.urls.registration_status
		headers = self.headers()
		payload = self.get_encrypted_payload(method="registration_status")

		response = self.post_request(url, headers=headers, payload=payload)

		log_id = create_api_log(
			response,
			action="Registration Status",
			account_config=self.get_account_config("registration_status"),
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			connector=self,
		)

		res = self.get_decrypted_response(
			response, method="registration_status", log_id=log_id
		)
		if res.status == "success":
			self.db_set("registration_status", "Registered")

		frappe.msgprint(res.message or _("Registration Status Fetched Failed"))

	def initiate_payment(self):
		self.update_client_details("make_payment")
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		# Bulk / OTP flows require a prior OTP UNIQUEID; composite no-OTP mints on initiate.
		otp = self._payment_otp(payment_details)
		unique_id = self._resolve_icici_unique_id(
			payment_details,
			required=bool(self.bulk_transaction or otp),
			mint_if_missing=not bool(self.bulk_transaction or otp),
		)

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers(payment_details.mode_of_transfer)
		account_config = self.get_account_config("make_payment")
		payload = self.get_encrypted_payload(
			method="make_payment", account_config=account_config
		)

		response = self.post_request(url, headers=headers, payload=payload)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=account_config,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		self.update_client_details("payment_status")
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = self._resolve_icici_unique_id(payment_details)

		mode_of_transfer = payment_details.mode_of_transfer

		url = self.urls.payment_status
		headers = self.headers(mode_of_transfer)
		account_config = self.get_account_config("payment_status")
		payload = self.get_encrypted_payload(
			method="payment_status", account_config=account_config
		)

		response = self.post_request(url, headers=headers, payload=payload)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=account_config,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def generate_otp(self):
		self.update_client_details("generate_otp")
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.generate_otp
		headers = self.headers(
			payment_details.get("mode_of_transfer") or self.doc.get("default_mode_of_transfer")
		)
		# Build config once — set_otp_data mints UNIQUEID; reusing config avoids a
		# second mint when logging (was sending one id to ICICI and storing another).
		account_config = self.get_account_config("generate_otp")
		payload = self.get_encrypted_payload(
			method="generate_otp", account_config=account_config
		)

		response = self.post_request(url, headers=headers, payload=payload)

		ref_doctype = payment_details.parenttype or payment_details.doctype or self.doc.get("doctype")
		ref_docname = payment_details.parent or payment_details.name or self.doc.get("name")

		log_id = create_api_log(
			response,
			action="Generate OTP",
			account_config=account_config,
			ref_doctype=ref_doctype,
			ref_docname=ref_docname,
			unique_id=account_config.get("UNIQUEID"),
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="generate_otp", log_id=log_id
		)

	def get_priority(self, mode_of_transfer):
		return {"RTGS": "0001", "IMPS": "0100"}.get(mode_of_transfer, "0010")

	def get_encrypted_payload(self, method, account_config=None):
		connector_doc = self

		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		data = account_config or self.get_account_config(method)
		public_key_path = self.get_file_relative_path(connector_doc.public_key)

		if method in self.HYBRID_ENCRYPTION_METHODS or (
			self.bulk_transaction and method not in ["bank_balance", "bank_statement"]
		):
			return self.get_hybrid_encrypted_payload(
				data, public_key_path, payment_details
			)

		return self.rsa_encrypt_data(data, public_key_path)

	def get_hybrid_encrypted_payload(self, data, public_key_path, payment_details):
		random_key = self.generate_16_digit_random_number()
		encrypted_key = self.icici_rsa_encrypt(random_key, public_key_path)
		encrypted_data = self.icici_aes_encrypt_data(
			data=data, key=random_key, iv=random_key
		)

		return json.dumps(
			{
				"requestId": self.generate_request_id(),
				"service": "",
				"encryptedKey": encrypted_key,
				"oaepHashingAlgorithm": "NONE",
				"iv": "",
				"encryptedData": encrypted_data,
				"clientInfo": "",
				"optionalParam": "",
			},
			separators=(",", ":"),
		)

	def generate_request_id(self):
		return "".join(
			secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(10)
		)

	def generate_16_digit_random_number(self):
		return "".join(secrets.choice("0123456789") for _ in range(16))

	def icici_rsa_encrypt(self, data, key_path):
		if isinstance(data, str):
			data = data.encode("utf-8")

		with open(key_path, "rb") as file:
			rsa_key = RSA.import_key(file.read())

		cipher = Cipher_PKCS1_v1_5.new(rsa_key)
		return b64encode(cipher.encrypt(data)).decode("utf-8")

	def icici_rsa_decrypt(self, data, key_path):
		with open(key_path, "rb") as file:
			rsa_key = RSA.import_key(file.read())

		cipher = Cipher_PKCS1_v1_5.new(rsa_key)
		decrypted = cipher.decrypt(b64decode(data), None)
		if decrypted is None:
			frappe.throw(_("Failed to decrypt ICICI encrypted key."))

		return decrypted.decode("utf-8")

	def icici_aes_encrypt_data(self, data, key, iv):
		if isinstance(data, dict):
			data = json.dumps(data, separators=(",", ":"))

		key = key.encode("utf-8") if isinstance(key, str) else key
		iv = iv.encode("utf-8") if isinstance(iv, str) else iv
		plain_text = data.encode("utf-8")
		cipher = AES.new(key, AES.MODE_CBC, iv)
		encrypted_data = cipher.encrypt(pad(plain_text, AES.block_size))

		return b64encode(iv + encrypted_data).decode("utf-8")

	def icici_aes_decrypt_data(self, data, key, json_loads=True):
		key = key.encode("utf-8") if isinstance(key, str) else key
		encrypted_bytes = b64decode(data)
		decryption_errors = []

		decryption_attempts = []
		if len(encrypted_bytes) > AES.block_size:
			decryption_attempts.append(
				(encrypted_bytes[: AES.block_size], encrypted_bytes[AES.block_size :])
			)
		decryption_attempts.append((self.IV, encrypted_bytes))

		for iv, encrypted_data in decryption_attempts:
			try:
				cipher = AES.new(key, AES.MODE_CBC, iv)
				decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
				if decrypted_data[: AES.block_size] == iv:
					decrypted_data = decrypted_data[AES.block_size :]
				decrypted_text = decrypted_data.decode("utf-8")
				return json.loads(decrypted_text) if json_loads else decrypted_text
			except Exception as e:
				decryption_errors.append(e)

		frappe.log_error("Connector Error", frappe.get_traceback(with_context=True))
		frappe.throw(title="Decryption Failed", msg=decryption_errors[0])

	def get_account_config(self, method):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		if "A2A" in payment_details.get("mode_of_transfer", ""):
			payment_details.mode_of_transfer = "Intra Bank Transfer"

		data = {}
		method_map = {
			"register": self.set_register_data,
			"registration_status": self.set_registration_status_data,
			"generate_otp": self.set_otp_data,
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method](data)

		return data

	def set_register_data(self, data):
		connector_doc = self
		data.update(
			{
				"AGGRNAME":connector_doc.aggr_name,
				"AGGRID":connector_doc.aggr_id,
				"CORPID":connector_doc.corp_id,
				"USERID":connector_doc.corp_usr,
				"URN":connector_doc.urn,
				"ALIASID":"",
			}
		)

	def set_registration_status_data(self, data):
		connector_doc = self
		data.update(
			{
				"AGGRNAME":connector_doc.aggr_name,
				"AGGRID":connector_doc.aggr_id,
				"CORPID":connector_doc.corp_id,
				"USERID":connector_doc.corp_usr,
				"URN":connector_doc.urn,
			}
		)

	def set_statement_data(self, data):
		connector_doc = self
		payload_details = self.doc

		from_date = getdate(payload_details.get("from_date", "")).strftime("%d-%m-%Y")
		to_date = getdate(payload_details.get("to_date", "")).strftime("%d-%m-%Y")

		data.update(
			{
				"AGGRID":connector_doc.aggr_id,
				"CORPID":connector_doc.corp_id,
				"USERID":connector_doc.statement_corp_usr,
				"URN":connector_doc.urn,
				"FROMDATE":from_date,
				"TODATE":to_date,
				"ACCOUNTNO":connector_doc.account_number,
			}
		)
		if payload_details.get("paginated"):
			data.update({"CONFLG": "N"})
		if payload_details.get("last_transaction_id"):
			data.update(
				{"CONFLG": "Y", "LASTTRID": payload_details.get("last_transaction_id")}
			)

	def set_balance_data(self, data):
		connector_doc = self

		data.update(
			{
				"AGGRID":connector_doc.aggr_id,
				"CORPID":connector_doc.corp_id,
				"USERID":connector_doc.balance_corp_usr,
				"URN":connector_doc.urn,
				"ACCOUNTNO":connector_doc.account_number,
			}
		)

	def _payment_order_doc(self):
		doc = self.doc or {}
		return frappe._dict(doc) if isinstance(doc, dict) else doc

	def _uses_bulk_file_status_inquiry(self):
		"""Bulk file status needs FILESEQNUM; composite-initiated POs do not have it."""
		if not self.bulk_transaction:
			return False
		po = self._payment_order_doc()
		return bool(po.get("file_sequence_number"))

	def _payment_status_summary_key(self):
		"""Summary row id for mapping composite status responses."""
		row_name = getattr(self.payment_doc, "name", None)
		if not row_name and hasattr(self.payment_doc, "get"):
			row_name = self.payment_doc.get("name")
		if row_name:
			return row_name

		po = self._payment_order_doc()
		for row in po.get("summary") or []:
			row = frappe._dict(row)
			if row.payment_initiated or row.payment_status in (
				"Initiated",
				"Processed",
				"Pending",
			):
				return row.name

		summary = po.get("summary") or []
		if summary:
			return frappe._dict(summary[0]).name

		return po.get("name")

	def _otp_session_key(self, payment_details):
		"""Session key for UNIQUEID persistence.

		Bulk: Payment Order name (one OTP / file per PO).
		Composite: Payment Order Summary row name (one UNIQUEID per payment line).
		"""
		if self.bulk_transaction:
			if hasattr(payment_details, "get"):
				return payment_details.get("name") or self._payment_order_doc().get("name")
			return payment_details.name

		# Composite: prefer summary row id so multi-PR POs get distinct UNIQUEIDs.
		row_name = payment_details.get("name") if hasattr(payment_details, "get") else getattr(
			payment_details, "name", None
		)
		if (
			payment_details.get("parenttype") == "Payment Order"
			and row_name
		):
			return row_name

		doc = payment_details.get("doc") or {}
		order_name = doc.get("name") if isinstance(doc, dict) else getattr(doc, "name", None)
		if order_name:
			return order_name

		if self.doc.get("name"):
			return self.doc.name

		return row_name

	def _otp_cache_key(self, session_key):
		return f"icici_otp_uniqueid_{session_key}"

	def _otp_unique_id_column_ready(self):
		return frappe.db.has_column("Payment Order", self.ICICI_OTP_UNIQUE_ID_FIELD)

	def _summary_unique_id_column_ready(self):
		return frappe.db.has_column(
			"Payment Order Summary", self.ICICI_SUMMARY_UNIQUE_ID_FIELD
		)

	def _is_summary_session_key(self, session_key):
		return bool(
			session_key
			and not self.bulk_transaction
			and frappe.db.exists("Payment Order Summary", session_key)
		)

	def _persist_otp_unique_id(self, session_key, unique_id):
		if not session_key:
			frappe.throw(_("Could not resolve ICICI UNIQUEID session key."))
		# Always keep cache first so initiate can continue even if DB row is locked.
		frappe.cache().set_value(
			self._otp_cache_key(session_key), unique_id, expires_in_sec=1800
		)

		try:
			# Composite: persist per Payment Order Summary row.
			if self._is_summary_session_key(session_key) and self._summary_unique_id_column_ready():
				frappe.db.set_value(
					"Payment Order Summary",
					session_key,
					self.ICICI_SUMMARY_UNIQUE_ID_FIELD,
					unique_id,
					update_modified=False,
				)
				return

			# Bulk / legacy: persist on Payment Order.
			if self._otp_unique_id_column_ready() and frappe.db.exists(
				"Payment Order", session_key
			):
				frappe.db.set_value(
					"Payment Order",
					session_key,
					self.ICICI_OTP_UNIQUE_ID_FIELD,
					unique_id,
					update_modified=False,
				)
		except Exception:
			# Lock wait / concurrent worker: cache still holds UNIQUEID for this request.
			frappe.log_error(
				title="ICICI UNIQUEID persist skipped",
				message=frappe.get_traceback(with_context=True),
			)

	def _get_persisted_otp_unique_id(self, session_key):
		if not session_key:
			return None

		if self._is_summary_session_key(session_key) and self._summary_unique_id_column_ready():
			unique_id = frappe.db.get_value(
				"Payment Order Summary",
				session_key,
				self.ICICI_SUMMARY_UNIQUE_ID_FIELD,
			)
			if unique_id:
				return unique_id

		if self._otp_unique_id_column_ready() and frappe.db.exists(
			"Payment Order", session_key
		):
			unique_id = frappe.db.get_value(
				"Payment Order", session_key, self.ICICI_OTP_UNIQUE_ID_FIELD
			)
			if unique_id:
				return unique_id

		return frappe.cache().get_value(self._otp_cache_key(session_key))

	def _mint_otp_unique_id(self, session_key):
		"""Mint UNIQUEID once per request; persist for payment + status steps."""
		if (
			getattr(self, "_request_otp_unique_id", None)
			and getattr(self, "_request_otp_session_key", None) == session_key
		):
			return self._request_otp_unique_id

		unique_id = "".join(
			secrets.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(16)
		)
		self._request_otp_unique_id = unique_id
		self._request_otp_session_key = session_key
		self._persist_otp_unique_id(session_key, unique_id)
		return unique_id

	def _unique_id_from_initiation_log(self, session_key):
		"""Look up UNIQUEID from a prior Initiate Payment log for this session."""
		ref_name = session_key
		if self._is_summary_session_key(session_key):
			# Composite logs are stored against the parent Payment Order.
			# Prefer an exact unique_id match against the summary-persisted value.
			persisted = None
			if self._summary_unique_id_column_ready():
				persisted = frappe.db.get_value(
					"Payment Order Summary",
					session_key,
					self.ICICI_SUMMARY_UNIQUE_ID_FIELD,
				)
			if persisted:
				return persisted
			return None

		logs = frappe.get_all(
			"Bank Request Log",
			filters={
				"action": "Initiate Payment",
				"reference_doctype": "Payment Order",
				"reference_docname": ref_name,
			},
			fields=["name", "unique_id", "config_details"],
			order_by="creation desc",
			limit=1,
		)
		if not logs:
			return None

		log = logs[0]
		if log.unique_id:
			return log.unique_id

		if not log.config_details:
			return None

		try:
			initiation_log = frappe.get_doc("Bank Request Log", log.name)
			config_details = initiation_log.decrypt_data(initiation_log.config_details)
			if isinstance(config_details, str):
				config_dict = json.loads(config_details)
			elif isinstance(config_details, dict):
				config_dict = config_details
			else:
				config_dict = {}
			return (
				config_dict.get("UNIQUEID") or config_dict.get("UNIQUE_ID")
				if isinstance(config_dict, dict)
				else None
			)
		except Exception:
			return None

	def _payment_otp(self, payment_details):
		otp = payment_details.get("otp") if hasattr(payment_details, "get") else None
		if not otp:
			doc = payment_details.get("doc") if hasattr(payment_details, "get") else {}
			otp = frappe._dict(doc or {}).get("otp")
		return cstr(otp or "").strip()

	def _resolve_icici_unique_id(
		self, payment_details, required=False, mint_if_missing=False
	):
		"""Resolve UNIQUEID for OTP / payment / status (composite and bulk)."""
		session_key = self._otp_session_key(payment_details)
		unique_id = self._get_persisted_otp_unique_id(session_key)
		if not unique_id:
			unique_id = self._unique_id_from_initiation_log(session_key)

		if not unique_id and mint_if_missing:
			unique_id = self._mint_otp_unique_id(session_key)

		if not unique_id and required:
			frappe.throw(
				_(
					"No active OTP session for Payment Order {0}. Please generate "
					"the OTP again before initiating the payment."
				).format(session_key)
			)

		if not unique_id:
			payment_name = payment_details.get("name") or getattr(
				payment_details, "name", ""
			)
			unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_name))

		return unique_id

	def set_otp_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		unique_id = self._mint_otp_unique_id(self._otp_session_key(payment_details))

		data.update(
			{
				"CORPID":connector_doc.corp_id,
				"USERID":connector_doc.corp_usr,
				"AGGRID":connector_doc.aggr_id,
				"AGGRNAME":connector_doc.aggr_name,
				"URN":connector_doc.urn,
				"UNIQUEID":unique_id,
			}
		)

		if self.bulk_transaction:
			data.update(
				{
					"AMOUNT": str(payment_details.total),
				}
			)

	def get_transaction_type(self, bank, mode_of_transfer=None):
		if bank == "ICICI Bank":
			return "TPA"
		if mode_of_transfer == "RTGS":
			return "RTG"
		if mode_of_transfer == "IMPS":
			return "IFS"

		return "RGS"

	def set_payment_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[
			-10:
		]

		if self.bulk_transaction:
			# Same persisted UNIQUEID as OTP; file name/description stay PO-based.
			unique_id = self._resolve_icici_unique_id(payment_details, required=True)
			data.update(
				{
					"FILE_DESCRIPTION": file_reference_id,
					"CORP_ID": connector_doc.corp_id,
					"USER_ID": connector_doc.corp_usr,
					"AGGR_ID": connector_doc.aggr_id,
					"AGGR_NAME": connector_doc.aggr_name,
					"URN": connector_doc.urn,
					"UNIQUE_ID": unique_id,
					"AGOTP": str(payment_details.otp),
					"FILE_NAME": f"{file_reference_id}.txt",
					"FILE_CONTENT": self.construct_payment_details_content(
						payment_details, connector_doc
					),
				}
			)
			return
		else:
			otp = self._payment_otp(payment_details)
			use_otp = bool(otp)

			if use_otp:
				# Legacy With-OTP composite: UNIQUEID must match OTP session.
				unique_id = self._resolve_icici_unique_id(
					payment_details, required=True
				)
				workflow_reqd = "Y"
				if payment_details.mode_of_transfer.lower() not in ["neft", "imps"]:
					workflow_reqd = "N"
				if not self.testing:
					workflow_reqd = "Y"
			else:
				# Without-OTP UAT / production composite payload.
				unique_id = self._resolve_icici_unique_id(
					payment_details, mint_if_missing=True
				)
				workflow_reqd = "N"

			ifsc = (
				(connector_doc.ifsc_code or "ICIC0000011")
				if payment_details.bank == "ICICI Bank"
				else payment_details.branch_code
			)

			payload = {
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"AGGRID": connector_doc.aggr_id,
				"URN": connector_doc.urn,
				"UNIQUEID": unique_id,
				"AMOUNT": cstr(payment_details.amount),
				"AGGRNAME": connector_doc.aggr_name,
				"DEBITACC": connector_doc.account_number,
				"CREDITACC": payment_details.bank_account_no,
				"IFSC": ifsc,
				"CURRENCY": "INR",
				"TXNTYPE": self.get_transaction_type(
					payment_details.bank,
					mode_of_transfer=payment_details.mode_of_transfer,
				),
				"PAYEENAME": self.clean_string(payment_details.account_name),
				"REMARKS": (
					f"{payment_details.party_type} "
					f"{self.clean_string(payment_details.party)}"
				),
				"WORKFLOW_REQD": workflow_reqd,
			}
			if use_otp:
				payload["OTP"] = otp
				payload["CUSTOMERINDUCED"] = "Y"

			data.update(payload)

	def set_payment_status_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = self._resolve_icici_unique_id(payment_details)

		if self._uses_bulk_file_status_inquiry():
			po = self._payment_order_doc()
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.status_corp_usr,
					"AGGRID": connector_doc.aggr_id,
					"URN": connector_doc.urn,
					"UNIQUEID": unique_id,
					"FILESEQNUM": po.get("file_sequence_number"),
					"ISENCRYPTED": "N",
				}
			)
			return

		# Composite / single-transaction status (no FILESEQNUM).
		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"UNIQUEID": unique_id,
			}
		)

	def get_decrypted_response(self, response, method, log_id=None):
		connector_doc = self
		res_dict = frappe._dict({})
		if response.ok:
			response = response.text

			response_json = self.get_response_json(response)
			if response_json and self.has_hybrid_encrypted_response(response_json):
				decrypted_data = self.decrypt_hybrid_response(
					response_json, self.get_file_relative_path(connector_doc.private_key)
				)
			elif response_json:
				# Plain JSON response (e.g., error response from gateway)
				decrypted_data = response_json
			else:
				decrypted_data = self.rsa_decrypt_data(
					response, self.get_file_relative_path(connector_doc.private_key)
				)

			self.set_decrypted_response(log_id, decrypted_data)

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def get_response_json(self, response):
		try:
			return json.loads(response)
		except Exception:
			return None

	def has_hybrid_encrypted_response(self, response):
		return self.get_encrypted_key(response) and self.get_encrypted_data(response)

	def decrypt_hybrid_response(self, response, private_key_path):
		decrypted_key = self.icici_rsa_decrypt(
			self.get_encrypted_key(response), private_key_path
		)

		return self.icici_aes_decrypt_data(
			self.get_encrypted_data(response), decrypted_key
		)

	def get_encrypted_key(self, data):
		return (
			data.get("encryptedKey")
			or data.get("ENCR_KEY")
			or data.get("encrypted_key")
			or data.get("encr_key")
		)

	def get_encrypted_data(self, data):
		return (
			data.get("encryptedData")
			or data.get("ENCR_DATA")
			or data.get("encrypted_data")
			or data.get("encr_data")
		)

	def get_formated_response(self, data, res_dict, method):
		if isinstance(data, str):
			data = json.loads(data)

		data = frappe._dict(data)

		use_bulk_handler = method in ["bank_balance", "bank_statement"] or (
			self.bulk_transaction
			and not (method == "payment_status" and not self._uses_bulk_file_status_inquiry())
		)
		if use_bulk_handler:
			self.handle_bulk_transaction_response(data, res_dict, method)
			return res_dict

		if method == "register":
			if data.get("RESPONSE") == "SUCCESS":
				res_dict.status = "success"
				res_dict.message = data.get("MESSAGE", "")
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errormessage") or data.get("Message")

		elif method == "registration_status":
			if data.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = data.get(
					"MESSAGE", "Registration Completed Successfully"
				)
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errormessage") or data.get("Message")

		elif method == "generate_otp" and data:
			if data.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = data.get("Message") or data.get("MESSAGE")
			else:
				res_dict.status = "Failed"
				err_msg = None
				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))
				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "make_payment" and data:
			# Prefer RESPONSE when present — UAT can return STATUS=PENDING with RESPONSE=FAILURE.
			response_flag = cstr(data.get("RESPONSE") or "").upper()
			if response_flag == "FAILURE":
				res_dict.payment_status = "FAILED"
				err_msg = ""
				if data.get("ERRORCODE") or data.get("ErrorCode"):
					err_msg = self.get_error_description(
						data.get("ERRORCODE") or data.get("ErrorCode")
					)
				res_message = (
					err_msg
					or data.get("MESSAGE")
					or data.get("errormessage")
					or data.get("Message")
					or data.get("STATUS")
				)
				res_dict.message = cstr(res_message)
				res_dict.summary_details = {
					self.payment_doc.name: {
						"payment_status": "Failed",
						"message": res_dict.message,
					}
				}
			elif data.STATUS in [
				"SUCCESS",
				"PENDING",
				"PENDING FOR PROCESSING",
				"PENDING FOR APPROVAL",
			]:
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = f"Payment {data.get('STATUS', '').title()}"
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Accepted"}
				}
			elif data.UTRNUMBER:
				res_dict.status = "ACCEPTED"
				res_dict.message = data.UTRNUMBER
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Accepted"}
				}
			elif data.STATUS == "DUPLICATE":
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = f"Payment {data.get('STATUS', '').title()}"
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Failed"}
				}
			elif data.errorCode == "997":
				res_dict.payment_status = "Request Failure"
				res_dict.message = f"{data.errorCode} : {data.description}"
			else:
				res_dict.payment_status = "FAILED"
				err_msg = ""
				if data.get("ERRORCODE") or data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ERRORCODE") or data.get("ErrorCode"))
				
				res_message = err_msg or data.get("MESSAGE") or data.get("errormessage") or data.get("Message")
				if res_message:
					res_dict.message = f"{data.STATUS.title()} : {res_message}"
				else:
					res_dict.message = f"Invalid Status : {data.STATUS}"

		elif method == "payment_status" and data:
			summary_key = self._payment_status_summary_key()
			if data.STATUS == "SUCCESS":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					summary_key: {
						"status": "Processed",
						"utr_number": data.UTRNUMBER,
						"message": data.MESSAGE or "Payment Completed",
					}
				}
			elif data.STATUS in ["PENDING", "PENDING FOR APPROVAL"]:
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					summary_key: {
						"status": "Pending",
						"message": data.MESSAGE or "Payment Pending",
					}
				}
			elif data.STATUS == "FAILURE":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					summary_key: {
						"status": "Failed",
						"message": data.MESSAGE or "Payment Failed",
					}
				}
			elif data.STATUS in ["UNKNOWN", "ERROR", "FAILED"]:
				# Invalid UNIQUEID / not found — do not treat as Processed.
				res_dict.payment_status = "FAILED"
				res_dict.message = data.MESSAGE or f"Status inquiry failed: {data.STATUS}"
				res_dict.summary_details = {
					summary_key: {
						"status": "Pending",
						"message": data.MESSAGE or f"Status inquiry failed: {data.STATUS}",
					}
				}
			else:
				res_dict.payment_status = "FAILED"
				res_dict.message = data.MESSAGE or f"Unhandled status: {data.STATUS}"
				res_dict.summary_details = {
					summary_key: {
						"status": "Request Failure",
						"message": data.MESSAGE or "Payment Request Failure",
					}
				}

	def handle_bulk_transaction_response(self, data, res_dict, method):
		if method == "generate_otp" and data:
			if data.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = data.get("MESSAGE")

			elif data.get("errormessage"):
				res_dict.status = "Failed"
				err_msg = None

				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))

				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "make_payment" and data:
			if data.get("FILE_SEQUENCE_NUM"):
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = data.get("MESSAGE_DESC")
				res_dict.file_sequence_number = data.get("FILE_SEQUENCE_NUM")

				res_dict.summary_details = self.get_summary_details("Accepted")

			elif data.get("errormessage") or data.get("ErrorCode"):
				res_dict.payment_status = "ACCEPTED"
				err_msg = ""

				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))
				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

				res_dict.summary_details = self.get_summary_details("Failed")

		elif method == "payment_status" and data:
			if file_status := data.get("XML", {}).get("FILE_STATUS"):
				res_dict.payment_status = "PROCESSED"
				if file_status in ["REJ", "REC"]:
					res_dict.message = "Payment Rejected"
				elif file_status in ["FAL"]:
					res_dict.message = "Payment Failed"

				res_dict.summary_details = {}

				if (
					data.get("XML")
					.get("FILEUPLOAD_BINARY_OUTPUT")
					.get("Records")
					.get("Record")
				):
					res_dict.summary_details = self.format_payment_status(
						data.get("XML", {})
						.get("FILEUPLOAD_BINARY_OUTPUT", {})
						.get("Records", {})
						.get("Record", "")
					)

			elif data.get("errormessage") or data.get("ErrorCode"):
				res_dict.status = "Failed"
				err_msg = None
				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))

				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "bank_balance" and data:
			if data.get("RESPONSE") == "SUCCESS":
				res_dict.server_status = "Success"
				res_dict.balance = data.get("EFFECTIVEBAL", 0)
				res_dict.date = data.get("DATE", "")
			else:
				res_dict.server_status = "Failed"
				res_dict.message = data

		elif method == "bank_statement" and data:
			records = data.get("Record", [])
			transactions = []

			if data.get("RESPONSE") == "SUCCESS":
				if isinstance(records, dict):
					records = [records]
				for txn in records:
					transaction = {
						"transaction_date": txn.get("TXNDATE", ""),
						"transaction_amount": txn.get("AMOUNT"),
						"reference_number": txn.get("TRANSACTIONID")
						or txn.get("CHEQUENO"),
						"transaction_description": txn.get("REMARKS", ""),
					}
					transactions.append(transaction)

			res_dict.server_status = "Success"
			res_dict.bank_statements = transactions
			res_dict.last_transaction_id = data.get("LISTTRID")

		return res_dict

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)

		response_data = json.dumps(response_data, indent=4)

		super().set_decrypted_response(log_id, response_data)

	def get_cert(self):
		return (
			self.get_file_relative_path(self.cert_file),
			self.get_file_relative_path(self.private_key),
		)

	def update_client_details(self, method=None):
		if not method:
			frappe.throw("Invalid Method")

		if method == "bank_balance":
			self.client_key = self.get_password("balance_client_key")
		elif method == "bank_statement":
			self.client_key = self.get_password("statement_client_key")
		else:
			self.client_key = self.get_password("client_key")

	def get_bank_balance(self):
		if not self.balance_check:
			frappe.throw(_("Bank Balance Check is not enabled."))

		self.update_client_details("bank_balance")
		url = self.urls.bank_balance
		headers = self.headers()
		payload = self.get_encrypted_payload(method="bank_balance")

		response = self.post_request(url, headers=headers, payload=payload)

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.get_account_config("bank_balance"),
			ref_doctype="Bank Balance",
			ref_docname=self.account_number,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_bank_statement(self):
		if not self.statement_fetch:
			frappe.throw(_("Bank Statement Check is not enabled."))

		self.update_client_details("bank_statement")
		url = self.urls.bank_statement
		headers = self.headers()
		payload = self.get_encrypted_payload(method="bank_statement")

		response = self.post_request(url, headers=headers, payload=payload)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.get_account_config("bank_statement"),
			ref_doctype="Bank Statement",
			ref_docname=self.account_number,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def get_error_description(self, code):
		return {
			"108363": "The entered date cannot be prior to the current date.",
			"108590": "The header amount does not equal the sum of records in the uploaded file.",
			"101043": "Type system exception occurred",
			"999481": "Dear Customer, This facility is available for select customer segments only. For any further queries please write to corporatecare@icicibank.com",
			"108588": "The total number of records is not same in header and file records.",
			"104668": "Please select the proper files and attach again.",
			"110370": "Please select the proper files and attach again.",
			"104344": "The cut-off time for this transaction has already passed. This action cannot be performed with the current transaction date.",
			"999936": "Transactions already processed with same unique ID, please use exclusive unique id for each transaction.",
			"111267": "The record ID is not present in the file.",
			"110004": "Enter the valid date as the selected date is a bank holiday.",
			"994006": "OTP Validation Failed",
			"107889": "OTP Validation Failed",
			"100901": "Consumption limits not defined for the user. Transaction cannot be processed. Please contact the bank administrator",
			"104666": "File with the same name is already uploaded",
		}.get(str(code), "Unknown Error")

	def construct_payment_details_content(self, payment_doc, connector_doc):
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_doc.name))[-10:]

		content = []
		first_line = "{}|{}|{}|{}|{}|{}|{}|{}^".format(
			"FHR",
			len(payment_doc.summary) + 1,
			getdate(nowdate()).strftime("%m/%d/%Y"),
			file_reference_id,
			flt(payment_doc.total),
			"INR",
			connector_doc.account_number,
			"0011",
		)
		content.append(first_line)
		second_line = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
			"MDR",
			connector_doc.account_number,
			"0011",
			payment_doc.company.replace(" ", "")[:30],
			flt(payment_doc.total),
			"INR",
			file_reference_id,
			"ICIC0000011",
			"WIB",
		)
		content.append(second_line)
		for payment_row in payment_doc.summary:
			if isinstance(payment_row, str):
				payment_row = json.loads(payment_row)
			payment_row = frappe._dict(payment_row)
			if payment_doc.company_bank == payment_row.bank:
				mcw_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
					"MCW",
					payment_row.bank_account_no,
					payment_row.bank_account_no[:4],
					payment_row.account_name.replace(" ", "")[:30],
					flt(payment_row.amount),
					"INR",
					payment_row.name,
					payment_row.branch_code,
					"WIB",
				)
				content.append(mcw_st)
			else:
				mco_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
					"MCO",
					payment_row.bank_account_no,
					"0011",
					payment_row.account_name.replace(" ", "")[:30],
					flt(payment_row.amount),
					"INR",
					payment_row.name,
					"NFT",
					payment_row.branch_code,
				)
				content.append(mco_st)
		result = "\n".join(content)
		byte_like = str.encode(result)
		encode_result = b64encode(byte_like).decode("utf-8")
		return encode_result

	def format_payment_status(self, records):
		if isinstance(records, str):
			records = json.loads(records)

		keys = [
			"transaction_type",
			"network_id",
			"credit_account_number",
			"debit_account_number",
			"ifsc_code",
			"currency",
			"total_amount",
			"host_reference_number",
			"host_response_code",
			"host_response_message",
			"transaction_remarks",
			"transaction_status",
		]

		result = {}
		for row in records[1:]:
			values = row.split("|")
			row_dict = dict(zip(keys, values))
			if row_dict.get("transaction_status", "") == "SUC":
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Processed",
							"utr_number": row_dict.get("host_reference_number", ""),
							"message": row_dict.get(
								"host_response_message", "Payment Accepted"
							),
						}
					}
				)
			if row_dict.get("transaction_status", "") == "FAL":
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Failed",
							"message": row_dict.get(
								"host_response_message", "Payment Failed"
							),
						}
					}
				)
			if row_dict.get("transaction_status", "") in ["REJ", "REC"]:
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Rejected",
							"message": row_dict.get(
								"host_response_message", "Payment Rejected"
							),
						}
					}
				)

		return result

	def get_file_status(self, key):
		return {
			"GIP": "This is the intermediate state where GFP batches gets executed",
			"PFI": "(Pending for insertion)This is the state where bulk has been upload and transaction is completed from front end aand awaiting for the batch process to be completed.",
			"ENT": "Entered state for the transaction once bulk transaction is initiated",
			"MIR": "Manual intervention required: - goes for reversal",
			"STS": "Success",
			"FAL": "Failure",
			"PPD": "Partially processed",
			"REJ": "Transaction has gone to rejected case",
			"ATH": "status after process scheduler batch run is completed. Its before GFP batch.",
			"CRP": "Credit reversal pending",
			"REC": "when initiator itself canceled or recalled the txn",
		}.get(key, "Unknown issue occured")
