__author__ = 'Robert Cope'

from binascii import hexlify
import struct

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class DNSMessage(object):
    __slots__ = ['header', 'questions', 'answer_rrs', 'authority_rrs', 'additional_rrs']

    def __init__(self, header=None, questions=None, answer_rrs=None, authority_rrs=None, additional_rrs=None):
        self.header = header
        self.questions = questions
        self.answer_rrs = answer_rrs
        self.authority_rrs = authority_rrs
        self.additional_rrs = additional_rrs

    def __str__(self):
        return """
        Header: {h}
        Questions: {q}
        Answer RRs: {ans}
        Authority RRs: {auth}
        Additional RRs: {addn}
        """.format(h=self.header, q=self.questions, ans=self.answer_rrs, auth=self.authority_rrs,
                   addn=self.additional_rrs)

    def copy(self, **kwargs):
        kwargs.update(self.__dict__)
        return self.__class__(**kwargs)

    @classmethod
    def copy_from(cls, other):
        return cls(header=other.header, questions=other.questions, answer_rrs=other.answer_rrs,
                   authority_rrs=other.authority_rrs, additional_rrs=other.additional_rrs)


class DNSFlags(object):
    __slots__ = ['is_response', 'opcode', 'is_authoritative_answer', 'is_truncated', 'is_recursion_desired',
                 'is_recursion_available', 'response_code']
     
    def __init__(self, is_response=None, opcode=None, is_authoritative_answer=None, is_truncated=None, 
                 is_recursion_desired=None, is_recursion_available=None, response_code=None):
        self.is_response = is_response
        self.opcode = opcode
        self.is_authoritative_answer = is_authoritative_answer
        self.is_truncated = is_truncated
        self.is_recursion_desired = is_recursion_desired
        self.is_recursion_available = is_recursion_available
        self.response_code = response_code
    
    @classmethod
    def from_raw_flags(cls, flags):
        is_response = bool(flags >> 15)
        opcode = (flags >> 11) & 0x0F
        is_auth_ans = bool((flags >> 10) & 0x1)
        is_trunc = bool((flags >> 9) & 0x1)
        is_rd = bool((flags >> 8) & 0x1)
        is_ra = bool((flags >> 7) & 0x1)
        response_code = flags & 0xF
        return cls(is_response, opcode, is_auth_ans, is_trunc, is_rd, is_ra, response_code)
    
    def __str__(self):
        return """
        Is Response: {isresp}
        Opcode: {opcode}
        Is Authoritative: {isauth}
        Is Truncated: {istrunc}
        Is Recursion Desired: {isrd}
        Is Recursion Available: {isra}
        Response Code: {rc}
        """.format(isresp=self.is_response,
                   opcode=self.opcode,
                   isauth=self.is_authoritative_answer,
                   istrunc=self.is_truncated,
                   isrd=self.is_recursion_desired,
                   isra=self.is_recursion_available,
                   rc=self.response_code)
    
    def copy(self, **kwargs):
        kwargs.update(self.__dict__)
        return self.__class__(**kwargs)

    @classmethod
    def copy_from(cls, other):
        return cls(is_response=other.is_response, opcode=other.opcode,
                   is_authoritative_answer=other.is_authoritative_answer, is_truncated=other.is_truncated,
                   is_recursion_desired=other.is_recursion_desired, is_recursion_available=other.is_recursion_available,
                   response_code=other.response_code)


class DNSHeader(object):
    __slots__ = ['message_id', 'flags', 'question_count', 'answer_count', 'authority_count', 'additional_count']

    def __init__(self, message_id=None, flags=0, question_count=None, answer_count=None, authority_count=None,
                 additional_count=None, flags_class=DNSFlags):
        self.message_id = message_id
        self.flags = flags_class.from_raw_flags(flags)
        self.question_count = question_count
        self.answer_count = answer_count
        self.authority_count = authority_count
        self.additional_count = additional_count

    def __str__(self):
        return """
        Message ID: {mid}
        Flags: {f}
        Question Count: {qc}
        Answer Count: {ansc}
        Authority Count: {authc}
        Additional Count: {addnc}
        """.format(mid=self.message_id,
                   f=self.flags,
                   qc=self.question_count,
                   ansc=self.answer_count,
                   authc=self.authority_count,
                   addnc=self.additional_count)

    def copy(self, **kwargs):
        kwargs.update(self.__dict__)
        return self.__class__(**kwargs)

    @classmethod
    def copy_from(cls, other):
        return cls(message_id=other.message_id, flags=other.flags, question_count=other.question_count,
                   answer_count=other.answer_count, authority_count=other.authority_count,
                   additional_count=other.additional_count)


class DNSQuestion(object):
    __slots__ = ['question_domain_name', 'record_type', 'record_class']

    def __init__(self, question_domain_name=None, record_type=None, record_class=None,):
        self.question_domain_name = question_domain_name
        self.record_type = record_type
        self.record_class = record_class

    def __str__(self):
        return """
        Question Domain Name: {qdn}
        Record Type: {rt}
        Record Class: {rc}
        """.format(qdn=self.question_domain_name, rt=self.record_type, rc=self.record_class)

    def copy(self, **kwargs):
        kwargs.update(self.__dict__)
        return self.__class__(**kwargs)

    @classmethod
    def copy_from(cls, other):
        return cls(question_domain_name=other.question_domain_name, record_type=other.record_type,
                   record_class=other.record_class)


class ARecordData(object):
    __slots__ = ['ipaddress', 'raw']

    def __init__(self, ipaddress, raw):
        self.ipaddress = ipaddress
        self.raw = raw

    def __str__(self):
        return """
        IP Address: {ip}
        """.format(ip=".".join([str(ord(c)) for c in self.ipaddress]))


class CNAMERecordData(object):
    __slots__ = ['alias', 'raw']

    def __init__(self, alias, raw):
        self.alias = alias
        self.raw = raw

    def __str__(self):
        return """
        Alias: {a}
        """.format(a=self.alias)


class NSRecordData(object):
    __slots__ = ['nameserver', 'raw']

    def __init__(self, nameserver, raw):
        self.nameserver = nameserver
        self.raw = raw

    def __str__(self):
        return """
        Nameserver: {ns}
        """.format(ns=self.nameserver)


class MXRecordData(object):
    __slots__ = ['preference', 'exchange', 'raw']

    def __init__(self, preference, exchange, raw):
        self.preference = preference
        self.exchange = exchange
        self.raw = raw

    def __str__(self):
        return """
        MX Preference: {p}
        MX Exchange: {ex}
        """.format(p=self.preference, ex=self.exchange)


class RawRecordData(object):
    __slots__ = ['raw']

    def __init__(self, raw):
        self.raw = raw

    def __str__(self):
        return """
        Raw Data: {rd}
        """.format(rd=hexlify(self.raw))

    @classmethod
    def parse_rdata(cls, rdata, _, __):
        return cls(rdata)


class DNSRecord(object):
    __slots__ = ['record_id', 'record_name', 'record_type', 'record_data', 'record_class', 'ttl']

    def __init__(self, record_id=None, record_name=None, record_type=None, record_class=None, record_data=None,
                 ttl=None):
        self.record_name = record_name
        self.record_id = record_id
        self.record_type = record_type
        self.record_class = record_class
        self.record_data = record_data
        self.ttl = ttl

    def __str__(self):
        return """
        Record ID (DB): {id}
        Record Name: {rn}
        Record Type: {rt}
        Record Class: {rc}
        Record Data: {rd}
        TTL: {ttl}
        """.format(id=self.record_id, rn=self.record_name, rt=self.record_type, rc=self.record_class,
                   rd=self.record_data, ttl=self.ttl)

    def copy(self, **kwargs):
        kwargs.update(self.__dict__)
        return self.__class__(**kwargs)

    @classmethod
    def copy_from(cls, other):
        return cls(record_id=other.record_id, record_name=other.record_name, record_type=other.record_type,
                   record_data=other.record_data, record_class=other.record_class, ttl=other.ttl)


class DBDNSRecord(Base):
    __tablename__ = 'dns_records'
    record_id = Column(Integer, primary_key=True)
    record_name = Column(String(256), nullable=False)
    record_type = Column(Integer, nullable=False)
    record_class = Column(Integer, nullable=False)
    record_data = Column(String(256))
    ttl = Column(Integer, nullable=False)

    def __str__(self):
        return """
        Record ID (DB): {id}
        Record Name: {rn}
        Record Type: {rt}
        Record Class: {rc}
        Record Data: {rd}
        TTL: {ttl}
        """.format(id=self.record_id, rn=self.record_name, rt=self.record_type, rc=self.record_class,
                   rd=hexlify(self.record_data), ttl=self.ttl)

    @classmethod
    def copy_from(cls, other):
        cls(record_id=other.record_id, record_name=other.record_name, record_type=other.record_type,
            record_class=other.record_class, record_data=other.record_data, ttl=other.ttl)