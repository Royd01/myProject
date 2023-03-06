//
//  NetworkService.swift
//  NetworkService (iOS)
//
//  Created by royd on 2022/08/31.
//

import Foundation
import Alamofire
import SwiftyJSON
import WebKit
import Firebase
import FirebaseCrashlytics

//http request -> response - success or fail -> success ->  handle res code -> res code == 1 or other code(error)
//http request fail : handle in NetworkService(400~500?)
//res code error : handle in viewModel or ViewController
///Alamofire wrapping class - 공통설정 적용(암호화, 헤더)
class NetworkService {
    
    static let service : NetworkService = NetworkService()
    let DEFAULT_TIME_OUT : TimeInterval = 15
    var observer: NSKeyValueObservation?
    
    init(){
        plainMSeq = UserDefaults.standard.string(forKey: Comm.MSEQ)
        if let plainMSeq = self.plainMSeq {
            Crashlytics.crashlytics().setUserID(plainMSeq)
        }
        
        if let plain = plainMSeq {
            mSeq = CryptoUtils.swiftyRSAEncrypt(textValue: plain, key: Comm.PEM_STRING_PUBLIC)
        }
        observer = UserDefaults.standard.observe(\.mSeq, options: [.new, .old], changeHandler: { (userDefault, value) in
            if let new = value.newValue {
                if new.count > 0 {
                    self.plainMSeq = new
                    Crashlytics.crashlytics().setUserID(new)
                }else{
                    self.plainMSeq = nil
                }
            }
        })
    }
    
    var mSeq : String = ""
    var plainMSeq : String? = nil {
        didSet {
            if let plain = plainMSeq, plain.count > 0 {
                self.mSeq = CryptoUtils.swiftyRSAEncrypt(textValue: plain, key: Comm.PEM_STRING_PUBLIC)
            }
        }
    }
    
    lazy var userAgent : String = {
        let prefix = WKWebView().value(forKey: "userAgent") as! String
        let additional = "\(Comm.USER_AGENT)\(Comm.USER_AGENT_VER)\(Comm.sAppBundleVer)\(Comm.USER_AGENT_MSEQ)"
        return prefix + additional
    }()
    
    lazy var appVer : String = {
        return Comm.sAppBundleVer
    }()
    
    
    /// Request당 한번 생성, 최초 생성된 randomAESKey를 이용해서 생성해야됨
    /// 여러번 호출 호출하면 RandomKey가 바뀌어 무쓸모
    /// - Parameter randomAESKey: request할때 생성한 randomAESKey
    /// - Returns: 최종 파라미터 전달의 S키
    func secureKey(randomAESKey:String)->String{
        let sDataObj:[String:AnyObject] = [
            "svc": "HOUSE_APP" as AnyObject,
            "key": randomAESKey as AnyObject,
        ]
        
        let jsonSdata: JSON = JSON(sDataObj)
        print("jsonSdata : \(jsonSdata)")
        
        // s RSA 암호화
        let sRsa:String! = CryptoUtils.swiftyRSAEncrypt(textValue: "\(jsonSdata)", key: Comm.PEM_STRING_PUBLIC)
        print("rsa : \(String(describing: sRsa!))")
        return sRsa
    }
}

extension NetworkService {
    
    func session(){
        //TODO: set session configure
    }
    
    /// 사용자 변경시 암호화된 mSeq 값 업데이트
    func updateMemberSeq(){
        plainMSeq = UserDefaults.standard.string(forKey: Comm.MSEQ)
    }
    
    /// 공용 헤더 - mSeq, user-agent, app-ver
    /// content-type 별도로 명시 안할 경우 application/x-www-form-urlencoded
    /// json으로 POST할 경우 "content-type":"application/json" 필수 추가
    /// - Returns: 공용 헤더
    func commonHeaders() -> HTTPHeaders{//TODO: 정확한건 문서 참조
        let headers : HTTPHeaders = ["mSeq":mSeq,//mSeq 사용여부 - 저장된 mSeq 있는지 확인해야됨
                                     "user-agent":userAgent+mSeq,
                                     "app-ver":"i_"+appVer]
        //default content type - urlencoded
        print("MemberSeq :" + mSeq)
        return headers
    }
    
    func reqeust(url:String)->URLRequest?{//result로 하는게 좋을지도?
        if let url = URL(string: url) {
            return URLRequest(url: url , cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        }else{
            //invalidURL
            //handleError
            return nil
        }
    }
    
    func GETReqeust(url:String, parameter:Parameters? = nil ,complete:@escaping APIResultHandler)->DataRequest{
        return AF.request(url,
                          method: .get,
                          parameters: parameter,
                          headers: commonHeaders())
    }
    
    func POSTRequest(url:String, parameter:Parameters? = nil ,complete:@escaping APIResultHandler)->DataRequest{
        return AF.request(url,
                          method: .post,
                          parameters: parameter,
                          headers: commonHeaders())
    }
    
    func GET(url:String, parameter:Parameters? = nil ,useHeader:Bool = true,complete:@escaping (Result<Data, Error>)->Void){//TODO: reponse 변경 > 상세
        print("Request(GET:JSON) to : " + url)
        let request = AF.request(url,
                                 method: .get,
                                 parameters: parameter,
                                 headers: useHeader ? commonHeaders() : nil)
        
        
        request.response { response in//TODO: responseDecodable 분리
            switch response.result {
            case .success(let responseData):
                do {
                    if responseData != nil {
                        let result = try JSONSerialization.jsonObject(with: responseData!, options: .fragmentsAllowed)
                        print("ParseResult : \(result)")
                    }
                }catch DecodingError.dataCorrupted(let context) {
                    print(context)
                } catch DecodingError.keyNotFound(let key, let context) {
                    print("Key '\(key)' not found:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch DecodingError.valueNotFound(let value, let context) {
                    print("Value '\(value)' not found:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch DecodingError.typeMismatch(let type, let context) {
                    print("Type '\(type)' mismatch:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch {
                    print("error: ", error)
                }
                
                if responseData != nil {
                    complete(.success(responseData!))
                }
            case .failure(let error):
                print("error : \(error.localizedDescription)")
                complete(.failure(error))
            }
        }
    }
    
    func GET <T:Codable> (url:String, parameter:Parameters? = nil, complete:@escaping (Result<T,Error>)->Void){
        print("Request(GET:Codable) to : " + url)
        let requset = AF.request(url,
                                 method: .get,
                                 parameters: parameter,
                                 headers: commonHeaders())
        requset.responseData { response in
            print("Response from : \(response.request?.url?.absoluteString)")
            switch response.result {
            case .success(let responseData) :
                print("Response Success : \(String(describing: String(data: responseData, encoding: .utf8)))")
                do {
                    let decoded = try JSONDecoder().decode(T.self, from: responseData)
                    complete(.success(decoded))
                }catch DecodingError.dataCorrupted(let context) {
                    print(context)
                } catch DecodingError.keyNotFound(let key, let context) {
                    print("Key '\(key)' not found:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch DecodingError.valueNotFound(let value, let context) {
                    print("Value '\(value)' not found:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch DecodingError.typeMismatch(let type, let context) {
                    print("Type '\(type)' mismatch:", context.debugDescription)
                    print("codingPath:", context.codingPath)
                } catch {
                    print("error: ", error)
                }
                
            case .failure(let error) : complete(.failure(error))
            }
        }
    }
    
    /// POST - 암호화 유무 기능 분리 필요함, Header - mSeq 사용여부
    /// JSON 으로 요청 하는 경우는 헤더 ContentType에 필히 contentType/json 추가해야됨
    /// - Parameters:
    ///   - url: request url
    ///   - parameter: parameter
    ///   - encrypt : 암호화 여부
    ///   - complete: completion closure
    func POST(url:String, parameter:Parameters? = nil, encrypt:Bool = false ,complete:@escaping (Result<JSON, Error>)->Void){
        
        var commonHeaders = commonHeaders()
        var request : DataRequest?
        
        
        if encrypt {
            let randomKey = CryptoUtils.generateDefaultRandomBytes()
            let iv = randomKey?.ivKey()
            
            //파라미터 AES128 암호화
            let encryptedData =  "\(JSON(parameter as Any))".encrytWithAEA128(iv: iv!)
            
            //s - rsa - key
            //b - aes - parameter
            let encryptedParam = ["s":secureKey(randomAESKey: randomKey!),//
                                  "b":encryptedData]
            
            commonHeaders.addContentType(type: .JSON)
            
            if let jsonData = JSON(encryptedParam).rawString()?.data(using: .utf8) {
                request = AF.upload(jsonData, to: url, method: .post, headers: commonHeaders)
            }
        }else{
            request = AF.request(url,
                                 method: .post,
                                 parameters: parameter,
                                 encoding: URLEncoding(destination: .httpBody),
                                 headers: commonHeaders)
        }
        
        
        if let request = request {
            request.response { response in//TODO: responseDecodable 분리
                
                if let body = response.request?.httpBody {
                    let string = String(data: body, encoding: .utf8)
                    print("Body : " + string!)
                }
                
                switch response.result {
                case .success(let responseData):
                    if let responseData = responseData {
                        print("Response Success : \(String(describing: String(data: responseData, encoding: .utf8)))")
                        if let httpResponse = response.response, httpResponse.statusCode >= 400 && httpResponse.statusCode <= 500 {
                            //TODO: handle error
                            //complete(.failure(Error))//HAError만들어야됨
                        }else{
                            do {
                                let result = try JSONSerialization.jsonObject(with: responseData, options: .fragmentsAllowed)
                                //TODO: Response 핸들링할 방법 생각해봐야됨, decodable이용해서 매핑여부나 ResponseHandler만들거나..
                                complete(.success(JSON(responseData)))
                            }catch DecodingError.dataCorrupted(let context) {
                                print(context)
                            } catch DecodingError.keyNotFound(let key, let context) {
                                print("Key '\(key)' not found:", context.debugDescription)
                                print("codingPath:", context.codingPath)
                            } catch DecodingError.valueNotFound(let value, let context) {
                                print("Value '\(value)' not found:", context.debugDescription)
                                print("codingPath:", context.codingPath)
                            } catch DecodingError.typeMismatch(let type, let context) {
                                print("Type '\(type)' mismatch:", context.debugDescription)
                                print("codingPath:", context.codingPath)
                            } catch {
                                print("error: ", error)
                            }
                        }
                    }else{//responseData is null
                        print("Response Data is null")//발생하면 안되는케이스 - 서버 reponse가 empty
                    }
                case .failure(let error):
                    print("Response Failure Error : \(error.localizedDescription)")
                    complete(.failure(error))
                }
            }
        }
    }
    
    func encryptParam(param:Parameters)->Parameters{
        let randomKey = CryptoUtils.generateDefaultRandomBytes()
        let iv = randomKey?.ivKey()
        
        //파라미터 AES128 암호화
        let encryptedData =  "\(JSON(param as Any))".encrytWithAEA128(iv: iv!)
        
        //s - rsa - key
        //b - aes - parameter
        let encryptedParam = ["s":secureKey(randomAESKey: randomKey!),//
                              "b":encryptedData]
        
        return encryptedParam
    }
    
    /// Decodable로 반환하는 POST
    /// - Parameters:
    ///   - url: url
    ///   - contnetType: content - type , urlEncode 작동안하나
    ///   - param: param
    ///   - complete: complete
    func POST <T:Codable> (url:String, contentType:HttpContentType = .UrlEncode, param:Parameters? = nil, usingCryption:Bool = false, complete:@escaping (Result<T,Error>)->Void){
        var header = commonHeaders()
        var encoder : ParameterEncoding?
        
        switch contentType {
        case .UrlEncode : encoder = URLEncoding(destination: .httpBody)
        case .JSON : encoder = JSONEncoding()
        case .MultiPart:
            break
        }
        
        var req : DataRequest?
        
        if let param = param, usingCryption {
            header.addContentType(type: .JSON)
            let encryptedParam = encryptParam(param: param)
            
            if let jsonData = JSON(encryptedParam).rawString()?.data(using: .utf8) {
                req = AF.upload(jsonData, to: url, method: .post, headers: header)
            }
            
        }else{
            req = AF.request(url, method: .post,
                             parameters: param,
                             encoding: encoder!,
                             headers: header)
        }
        
        if let req = req {
            req.responseData { response in
                switch response.result {
                case .success(let responseData) :
                    print("Response Success : \(String(describing: String(data: responseData, encoding: .utf8)))")
                    do {
                        let decoded = try JSONDecoder().decode(T.self, from: responseData)
                        complete(.success(decoded))
                    }catch DecodingError.dataCorrupted(let context) {
                        print(context)
                    } catch DecodingError.keyNotFound(let key, let context) {
                        print("Key '\(key)' not found:", context.debugDescription)
                        print("codingPath:", context.codingPath)
                    } catch DecodingError.valueNotFound(let value, let context) {
                        print("Value '\(value)' not found:", context.debugDescription)
                        print("codingPath:", context.codingPath)
                    } catch DecodingError.typeMismatch(let type, let context) {
                        print("Type '\(type)' mismatch:", context.debugDescription)
                        print("codingPath:", context.codingPath)
                    } catch {
                        print("error: ", error)
                    }
                    
                case .failure(let error) : complete(.failure(error))
                }
            }
        }else{
            
        }
        
    }
}// NetworkService end

enum HttpContentType : String{
    case JSON = "Application/json"
    case MultiPart = "multipart/form-data"
    case UrlEncode = "Application/x-www-form-urlencode"
}

enum SuccessfulResponses : String{
    case OK = "200"
    case Created = "201"
    case Accepted = "202"
    case NonAuthoritativeInformation = "203"
    case NoContent = "204"
    case ResetContent = "205"
    case PartialContent = "206"
}

enum ClientErrorResponses : String{
    case BadRequest = "400"
    case Unauthorized = "401"
    case PaymentRequiredExperimental = "402"
    case Forbidden = "403"
    case NotFound = "404"
    case MethodNotAllowed = "405"
    case NotAcceptable = "406"
    case ProxyAuthenticationRequired = "407"
    case RequestTimeout = "408"
    case Conflict = "409"
    case Gone = "410"
    case LengthRequired = "411"
    case PreconditionFailed = "412"
    case PayloadTooLarge = "413"
    case URITooLong = "414"
}

enum ServerErrorResponses : String{
    case InternalServerError = "500"
    case NotImplemented = "501"
    case BadGateway = "502"
    case ServiceUnavailable = "503"
    case GatewayTimeout = "504"
    case HTTPVersionNotSupported = "505"
    case VariantAlsoNegotiates = "506"
    case InsufficientStorage = "507"
    case LoopDetected = "508"
    case NotExtended = "510"
    case NetworkAuthenticationRequired = "511"
}

extension HTTPHeaders {
    mutating func addContentType(type:HttpContentType){
        add(name: "content-type", value: type.rawValue)
    }
}

