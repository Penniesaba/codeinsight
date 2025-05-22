/**
 * @name CWE-295: 证书验证不当
 * @description 检测使用ssl._create_unverified_context()函数绕过SSL证书验证的情况
 * @kind problem
 * @problem.severity warning
 * @id python/certificate-validation-bypass
 * @tags security
 *       external/cwe/cwe-295
 */

import python

from Call call
where
  // 情况1：直接调用 _create_unverified_context()
  (
    call.getFunc() instanceof Name and
    call.getFunc().(Name).getId() = "_create_unverified_context"
  )

  // 情况2：调用 ssl._create_unverified_context()
  or (
    call.getFunc() instanceof Attribute and
    call.getFunc().(Attribute).getAttr() = "_create_unverified_context"
  )
select call, "检测到CWE-295漏洞：使用ssl._create_unverified_context()绕过SSL证书验证，可能导致中间人攻击"
