# API-Security

## Процесс подключения 

Процесс получения доступа к POS-Installment Partners API от OTP Bank включает в себя следующие шаги:

1. Подача заявки на подключение к тестовому API
1. Получение token + API secret по СМС на номер ответсвенного специалиста по технической части
1. Интеграция с API в тестовом окружении
1. Прохождение тестов, OTP Bank отправляет тест кейсы
1. Партнер и OTP Bank заключают договор, после чего все данные из договора используются для подключения. Token и API Secret отправляются партнеру на завершающем этапе подключения как Viber/SMS сообщение

<!-- theme: warning -->
> ### Важно
> Храните token и API Secret в защищенном хранилище. Получение злоумышленниками доступа к паре клюей ведет к рискам Fraud атак. 
> При компроментации token и API Secret необходимо обратиться к техническим контактам для отзыва старый и генерации новых ключей.

## Настройки безопасности при подключении к API

### Authorization Header

Token, который передается при подключении к API содержит в себе следующую информацию:
- access role - набор правил для доступа к определенным API
- partnerId - ID  партнера внутри OTP Bank
- Key ID - ID секретного ключа

<!-- theme: info -->
> Token и API Secret только в паре. Невозможно использовать Token и API Secret, выданные в разное время

Token должен передаваться в Authorization Header при каждого запросе к API.

### X-Signature Header

Для защиты от Man-in-the-middle атак, каждый запрос к POS Installments API должен содержать header X-Signature, который подтверждает целостность данных и авторство Партнера.

Процесс генерации 

X-Signature = base64(HMAC(Key, Message)), где

Key = {APISecret},
Message = X-Request-ID + URI + Content Body
Algorithm - SHA256

#### Примеры формирования Message

```
GET  https://base.url/partner/installments/orders/123452113/state
X-Request-ID: e3335fe5-a343-4d6d-a05b-aef7398cb9e7
```
```
Message = "e3335fe5-a343-4d6d-a05b-aef7398cb9e7/partner/installments/orders/123452113/state"
```
---
```
POST  https://base.url/partner/installments/orders/123452113/sent
X-Request-ID: e3335fe5-a343-4d6d-a05b-aef7398cb9e7

{"sentAt": "2021-09-01T01:01:00.000Z"}
```
```
Message = "e3335fe5-a343-4d6d-a05b-aef7398cb9e7/partner/installments/orders/123452113/sent{"sentAt": "2021-09-01T01:01:00.000Z"}"
```
