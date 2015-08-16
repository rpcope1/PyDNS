import struct

import hexdump

from PyDNS.models import DNSQuestion, DNSRecord, DNSHeader, DNSMessage, ARecordData, NSRecordData, CNAMERecordData, \
    MXRecordData, RawRecordData

__author__ = 'rcope'


def parse_label(label_len, raw_data, current_index):
    return raw_data[current_index+1:current_index+label_len+1], current_index + label_len + 1


def parse_pointer(raw_data, running_index, get_offset=True):
    if get_offset:
        offset = struct.unpack("!H", raw_data[running_index:running_index+2])[0] & 0x3FFF
        running_index = offset
    labels = []
    while raw_data[running_index] != '\x00':
        current_ordinal = ord(raw_data[running_index])
        if current_ordinal & 0xC0:
            new_labels, _ = parse_pointer(raw_data, running_index)
            labels.extend(new_labels)
            running_index += 2
            break
        else:
            label, running_index = parse_label(current_ordinal, raw_data, running_index)
            labels.append(label)
    return labels, running_index


def parse_dns_question(raw_message_data, current_index):
    names, running_index = parse_pointer(raw_message_data, current_index, get_offset=False)
    question_domain_name = ".".join(names)
    record_type, record_class = struct.unpack("!HH", raw_message_data[running_index:running_index+4])
    question = DNSQuestion(question_domain_name, record_type, record_class)
    print question
    return question, running_index+5


def parse_dns_rr(raw_message_data, current_index):
    names, running_index = parse_pointer(raw_message_data, current_index, get_offset=False)
    record_name = ".".join(names)
    record_type, record_class, record_ttl, rd_len =\
        struct.unpack("!HHIH", raw_message_data[running_index:running_index+10])
    end_rr = running_index+10+rd_len
    rdata = handle_record_data(raw_message_data[running_index+10:end_rr], record_type, raw_message_data, running_index+10)
    record = DNSRecord(None, record_name, record_type, record_class, rdata, record_ttl)
    print record
    return record, end_rr+1


def parse_dns_message(raw_data):
    transaction_id, flags, question_count, answer_rr_count, authority_rr_count, additional_rr_count = \
        struct.unpack("!HHHHHH", raw_data[:12])
    print
    hexdump.hexdump(raw_data)
    header = DNSHeader(transaction_id, flags, question_count, answer_rr_count, authority_rr_count, additional_rr_count)
    print header
    current_index = 12
    questions = [None]*question_count
    answer_rrs = [None]*answer_rr_count
    authority_rrs = [None]*authority_rr_count
    additional_rrs = [None]*additional_rr_count
    print "Questions"
    for i in xrange(question_count):
        question, current_index = parse_dns_question(raw_data, current_index)
        questions[i] = question
    print "Answers"
    for i in xrange(answer_rr_count):
        answer, current_index = parse_dns_rr(raw_data, current_index)
        answer_rrs[i] = answer
    print "Authorities"
    for i in xrange(authority_rr_count):
        authority, current_index = parse_dns_rr(raw_data, current_index)
        authority_rrs[i] = authority
    print "Additional"
    for i in xrange(additional_rr_count):
        additional_rr, current_index = parse_dns_rr(raw_data, current_index)
        additional_rrs[i] = additional_rr
    message = DNSMessage(header, questions, answer_rrs, authority_rrs, additional_rrs)
    return message


def handle_record_data(record_data, record_type, raw_message_data, current_index):
    if record_type == 0x01:
        ARecordData(record_data[:4], record_data)
    elif record_type == 0x02:
        labels = parse_pointer(raw_message_data, current_index, get_offset=False)
        return NSRecordData(".".join(labels), record_data)
    elif record_type == 0x05:
        labels = parse_pointer(raw_message_data, current_index, get_offset=False)
        return CNAMERecordData(".".join(labels), record_data)
    elif record_type == 0x0F:
        preference, = struct.unpack("!H", record_data[:2])
        exchange = parse_pointer(raw_message_data, current_index, get_offset=False)
        return MXRecordData(preference, exchange, record_data)
    else:
        return RawRecordData(record_data)