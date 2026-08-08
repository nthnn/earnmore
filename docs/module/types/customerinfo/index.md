---
title: CustomerInfo
kind: interface
longname: module:types.CustomerInfo
---

# CustomerInfo

<Signature
  code="interface CustomerInfo {
	address: CustomerAddress;
	birthday: Date;
	birthPlace: string;
	firstName: string;
	idDocument: IdDocument;
	lastName: string;
	middleName: string;
}"
/>

<SourceLink href="/source/types-ts/#L109" label="types.ts:109" />

---

## Properties

<MemberHeading id="address" depth="3" name="address" sig="address: CustomerAddress" />

<MemberMeta sourceHref="/source/types-ts/#L128" sourceLabel="types.ts:128" />

<MemberHeading id="birthday" depth="3" name="birthday" sig="birthday: Date" />

<MemberMeta sourceHref="/source/types-ts/#L117" sourceLabel="types.ts:117" />

Date of birth

<MemberHeading id="birthplace" depth="3" name="birthPlace" sig="birthPlace: string" />

<MemberMeta sourceHref="/source/types-ts/#L123" sourceLabel="types.ts:123" />

Place of birth — letters and spaces only (e.g. "New York", "Manila"). The library will throw if this contains digits or special characters.

<MemberHeading id="firstname" depth="3" name="firstName" sig="firstName: string" />

<MemberMeta sourceHref="/source/types-ts/#L110" sourceLabel="types.ts:110" />

<MemberHeading id="iddocument" depth="3" name="idDocument" sig="idDocument: IdDocument" />

<MemberMeta sourceHref="/source/types-ts/#L126" sourceLabel="types.ts:126" />

Primary identification document

<MemberHeading id="lastname" depth="3" name="lastName" sig="lastName: string" />

<MemberMeta sourceHref="/source/types-ts/#L111" sourceLabel="types.ts:111" />

<MemberHeading id="middlename" depth="3" name="middleName" sig="middleName: string" />

<MemberMeta sourceHref="/source/types-ts/#L114" sourceLabel="types.ts:114" />

Pass an empty string if the customer has no middle name
