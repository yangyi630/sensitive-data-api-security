def mask_phone(phone: str) -> str:
    """脱敏手机号: 138****1234"""
    if not phone or len(phone) < 11:
        return phone
    return f"{phone[:3]}****{phone[-4:]}"

def mask_id_card(id_card: str) -> str:
    """脱敏身份证: 110***********1234"""
    if not id_card or len(id_card) < 18:
        return id_card
    return f"{id_card[:3]}***********{id_card[-4:]}"

def mask_bank_card(bank_card: str) -> str:
    """脱敏银行卡: 6222**********1234"""
    if not bank_card or len(bank_card) < 16:
        return bank_card
    return f"{bank_card[:4]}**********{bank_card[-4:]}"

def mask_email(email: str) -> str:
    """脱敏邮箱: t***@example.com"""
    if not email or '@' not in email:
        return email
    parts = email.split('@')
    if len(parts[0]) <= 1:
        return f"*@{parts[1]}"
    return f"{parts[0][0]}***@{parts[1]}"

def mask_sensitive_data(data: str, field_type: str) -> str:
    """根据字段类型脱敏敏感数据"""
    if field_type == "phone":
        return mask_phone(data)
    elif field_type == "id_card":
        return mask_id_card(data)
    elif field_type == "bank_card":
        return mask_bank_card(data)
    elif field_type == "email":
        return mask_email(data)
    return data