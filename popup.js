document.addEventListener('DOMContentLoaded', () => {
  const copyNotice = document.getElementById('copyNotice');
  const statusElement = document.getElementById('status');
  const currentDomainElement = document.getElementById('currentDomain');
  const currentUAElement = document.getElementById('currentUA');
  const currentCookieElement = document.getElementById('currentCookie');
  const copyDomainBtn = document.getElementById('copyDomainBtn');
  const copyCookieBtn = document.getElementById('copyCookieBtn');
  const copyUABtn = document.getElementById('copyUABtn');
  const deleteCookiesBtn = document.getElementById('deleteCookiesBtn');
  const importCookiesBtn = document.getElementById('importCookiesBtn');
  const importModal = document.getElementById('importModal');
  const cookieInput = document.getElementById('cookieInput');
  const confirmImportBtn = document.getElementById('confirmImportBtn');
  const cancelImportBtn = document.getElementById('cancelImportBtn');
  
  // 检查是否是第一次使用
  chrome.storage.local.get(['firstTimeUse'], (result) => {
    if (result.firstTimeUse === undefined) {
      // 如果是第一次使用，显示公告
      document.getElementById('firstTimeAnnouncement').style.display = 'block';
      
      // 标记为已经看过公告
      chrome.storage.local.set({firstTimeUse: true}, () => {
        console.log('已标记为非首次使用');
      });
      
      // 添加关闭公告的点击事件
      document.getElementById('closeAnnouncement').addEventListener('click', () => {
        document.getElementById('firstTimeAnnouncement').style.display = 'none';
      });
    }
  });
  
  // 当前页面信息
  let currentPageInfo = {
    url: '',
    domain: '',
    userAgent: '',
    protocol: '',
    cookie: ''
  };
  
  // 获取当前标签页信息
  loadCurrentTabInfo();
  
  // 设置自动刷新 - 每3秒更新一次当前页面信息
  setInterval(loadCurrentTabInfo, 3000);
  
  // 为点击事件添加监听器
  copyDomainBtn.addEventListener('click', () => {
    copyDomain();
  });
  
  copyCookieBtn.addEventListener('click', () => {
    copyCookie();
  });
  
  copyUABtn.addEventListener('click', () => {
    copyUA();
  });
  
  deleteCookiesBtn.addEventListener('click', () => {
    // 先刷新当前页面信息，确保是最新的
    loadCurrentTabInfo();
    setTimeout(() => {
      deleteSiteCookies();
    }, 100);
  });
  
  importCookiesBtn.addEventListener('click', () => {
    // 先刷新当前页面信息，确保是最新的
    loadCurrentTabInfo();
    setTimeout(() => {
      showImportModal();
    }, 100);
  });
  
  confirmImportBtn.addEventListener('click', () => {
    importCookies();
  });
  
  cancelImportBtn.addEventListener('click', () => {
    hideImportModal();
  });
  
  // 点击模态框外部关闭
  importModal.addEventListener('click', (e) => {
    if (e.target === importModal) {
      hideImportModal();
    }
  });
  
  // 复制域名 (带协议)
  function copyDomain() {
    const fullDomain = `${currentPageInfo.protocol}//${currentPageInfo.domain}`;
    navigator.clipboard.writeText(fullDomain).then(() => {
      showCopyNotice(`已复制 ${fullDomain} 到剪贴板`);
    });
  }
  
  // 复制Cookie
  function copyCookie() {
    if (currentPageInfo.cookie) {
      navigator.clipboard.writeText(currentPageInfo.cookie).then(() => {
        showCopyNotice('已复制Cookie到剪贴板');
      });
    } else {
      showStatus('当前没有可用的Cookie', 'error');
    }
  }
  
  // 复制UA
  function copyUA() {
    if (currentPageInfo.userAgent) {
      navigator.clipboard.writeText(currentPageInfo.userAgent).then(() => {
        showCopyNotice('已复制User Agent到剪贴板');
      });
    } else {
      showStatus('User Agent信息不可用', 'error');
    }
  }
  
  // 删除当前站点所有Cookie
  function deleteSiteCookies() {
    if (!currentPageInfo.domain || currentPageInfo.domain === '浏览器内部页面') {
      showStatus('无法删除浏览器内部页面的Cookie', 'error');
      return;
    }
    
    if (confirm(`确定要删除 ${currentPageInfo.domain} 的所有Cookie吗？\n这将导致您在该网站的登录状态失效。`)) {
      let allCookies = [];
      let pendingRequests = 0;
      let requestsCompleted = 0;
      
      // 定义需要查询的域名列表（与getCookiesFromAPI相同的逻辑）
      const domainsToCheck = [];
      const domain = currentPageInfo.domain;
      
      domainsToCheck.push(domain);
      
      const baseDomain = getBaseDomain(domain);
      if (baseDomain !== domain) {
        domainsToCheck.push(baseDomain);
        domainsToCheck.push('.' + baseDomain);
      }
      
      domainsToCheck.push('.' + domain);
      
      const domainParts = domain.split('.');
      for (let i = 1; i < domainParts.length - 1; i++) {
        const subDomain = domainParts.slice(i).join('.');
        domainsToCheck.push(subDomain);
        domainsToCheck.push('.' + subDomain);
      }
      
      const uniqueDomains = [...new Set(domainsToCheck)];
      pendingRequests = uniqueDomains.length + 1;
      
      const checkCompletion = () => {
        requestsCompleted++;
        if (requestsCompleted === pendingRequests) {
          if (allCookies.length > 0) {
            // 去重
            const uniqueCookies = removeDuplicateCookies(allCookies);
            deleteCookieList(uniqueCookies);
          } else {
            showStatus('当前站点没有Cookie可删除', 'error');
          }
        }
      };
      
      // 查询每个域名的Cookie
      uniqueDomains.forEach(d => {
        chrome.cookies.getAll({ domain: d }, (cookies) => {
          if (cookies && cookies.length > 0) {
            allCookies = allCookies.concat(cookies);
          }
          checkCompletion();
        });
      });
      
      // 基于URL查询
      chrome.cookies.getAll({ url: currentPageInfo.url }, (cookies) => {
        if (cookies && cookies.length > 0) {
          allCookies = allCookies.concat(cookies);
        }
        checkCompletion();
      });
    }
  }
  
  // 删除Cookie列表
  function deleteCookieList(cookies) {
    let deletedCount = 0;
    let totalCount = cookies.length;
    
    cookies.forEach(cookie => {
      const url = `${cookie.secure ? 'https' : 'http'}://${cookie.domain}${cookie.path}`;
      chrome.cookies.remove({
        url: url,
        name: cookie.name
      }, (details) => {
        if (details) {
          deletedCount++;
        }
        
        // 检查是否所有Cookie都已处理
        if (deletedCount + (totalCount - deletedCount) === totalCount) {
          if (deletedCount > 0) {
            showStatus(`成功删除 ${deletedCount} 个Cookie`, 'success');
            // 刷新Cookie显示
            setTimeout(loadCurrentTabInfo, 500);
          } else {
            showStatus('删除Cookie失败', 'error');
          }
        }
      });
    });
  }
  
  // 显示导入模态框
  function showImportModal() {
    if (!currentPageInfo.domain || currentPageInfo.domain === '浏览器内部页面') {
      showStatus('无法为浏览器内部页面导入Cookie', 'error');
      return;
    }
    
    cookieInput.value = '';
    
    // 根据当前网站类型提供提示
    if (currentPageInfo.domain) {
      let placeholder = '例如：\n';
      
      // 检查是否可能是NexusPHP站点
      const currentCookieText = currentCookieElement.textContent;
      if (currentCookieText.includes('c_secure_') || !currentCookieText || currentCookieText === '当前站点没有Cookie') {
        placeholder += 'c_secure_uid=123456; c_secure_pass=abcdef\n';
        placeholder += 'c_secure_ssl=eWVhaA%3D%3D\n';
        placeholder += 'cf_clearance=xyz123';
      } else if (currentCookieText.includes('wordpress_')) {
        placeholder += 'wordpress_logged_in=username|1234567890|hash\n';
        placeholder += 'wordpress_sec=token_value';
      } else {
        placeholder += 'PHPSESSID=abc123def456\n';
        placeholder += 'auth_token=your_token_here';
      }
      
      cookieInput.placeholder = placeholder;
    }
    
    importModal.style.display = 'block';
  }
  
  // 隐藏导入模态框
  function hideImportModal() {
    importModal.style.display = 'none';
    cookieInput.value = '';
  }
  
  // 导入Cookie
  async function importCookies() {
    const cookieString = cookieInput.value.trim();
    
    if (!cookieString) {
      showStatus('请输入Cookie字符串', 'error');
      return;
    }
    
    // 解析Cookie字符串
    const cookies = parseCookieString(cookieString);
    
    if (cookies.length === 0) {
      showStatus('Cookie格式不正确', 'error');
      return;
    }
    
    let importedCount = 0;
    let failedCount = 0;
    let totalCount = cookies.length;
    let processedCount = 0;
    
    // 显示导入中状态
    showStatus(`正在导入 ${totalCount} 个Cookie...`, 'info');
    
    for (const cookie of cookies) {
      try {
        // 先尝试删除同名的旧Cookie
        await removeExistingCookie(cookie.name);
        
        // 尝试多种域名设置策略
        const domainStrategies = getDomainStrategies(currentPageInfo.domain);
        let imported = false;
        
        for (const domain of domainStrategies) {
          if (imported) break;
          
          // 构建Cookie设置参数
          const cookieDetails = {
            url: `${currentPageInfo.protocol}//${currentPageInfo.domain}`,
            name: cookie.name,
            value: cookie.value,
            path: '/',
            httpOnly: false,
            secure: currentPageInfo.protocol === 'https:'
          };
          
          // 根据Cookie类型设置特定参数
          if (cookie.name === 'cf_clearance' || cookie.name.startsWith('__cf')) {
            // Cloudflare Cookie需要特殊设置
            cookieDetails.sameSite = 'none';
            cookieDetails.secure = true;
          } else if (cookie.name.startsWith('c_secure_')) {
            // NexusPHP Cookie
            cookieDetails.sameSite = 'lax';
          } else if (cookie.name === 'sl-session') {
            // Session Cookie
            cookieDetails.sameSite = 'lax';
          } else {
            // 其他Cookie使用最宽松的策略
            cookieDetails.sameSite = 'no_restriction';
          }
          
          // 只在域名不以数字开头时设置domain（IP地址不需要domain）
          if (!/^\d/.test(domain)) {
            cookieDetails.domain = domain;
          }
          
          // 设置过期时间
          if (cookie.name.includes('session') || cookie.name === 'PHPSESSID') {
            // Session Cookie - 浏览器关闭时过期（不设置expirationDate）
          } else {
            // 其他Cookie - 默认30天
            cookieDetails.expirationDate = Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60);
          }
          
          // 尝试设置Cookie
          const success = await setCookiePromise(cookieDetails);
          if (success) {
            imported = true;
            importedCount++;
            console.log(`Successfully imported cookie: ${cookie.name} with domain: ${domain || 'default'}`);
          }
        }
        
        if (!imported) {
          failedCount++;
          console.error(`Failed to import cookie: ${cookie.name}`);
        }
      } catch (error) {
        failedCount++;
        console.error(`Error importing cookie ${cookie.name}:`, error);
      }
      
      processedCount++;
      
      // 更新进度
      if (processedCount % 5 === 0 || processedCount === totalCount) {
        showStatus(`正在导入... (${processedCount}/${totalCount})`, 'info');
      }
    }
    
    // 显示最终结果
    if (importedCount > 0) {
      let message = `成功导入 ${importedCount} 个Cookie`;
      if (failedCount > 0) {
        message += `，${failedCount} 个失败`;
      }
      showStatus(message, 'success');
      hideImportModal();
      // 刷新Cookie显示
      setTimeout(loadCurrentTabInfo, 500);
    } else {
      showStatus(`导入失败：无法导入任何Cookie`, 'error');
    }
  }
  
  // 删除已存在的同名Cookie
  async function removeExistingCookie(cookieName) {
    const domainStrategies = getDomainStrategies(currentPageInfo.domain);
    
    for (const domain of domainStrategies) {
      try {
        const url = `${currentPageInfo.protocol}//${currentPageInfo.domain}`;
        await new Promise((resolve) => {
          chrome.cookies.remove({
            url: url,
            name: cookieName
          }, () => resolve());
        });
      } catch (error) {
        // 忽略删除错误
      }
    }
  }
  
  // 获取域名策略列表
  function getDomainStrategies(domain) {
    const strategies = [];
    
    // 1. 原始域名
    strategies.push(domain);
    
    // 2. 如果是IP地址，只使用IP本身
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
      return strategies;
    }
    
    // 3. 带点前缀的域名（用于子域名共享）
    strategies.push('.' + domain);
    
    // 4. 获取基础域名
    const baseDomain = getBaseDomain(domain);
    if (baseDomain !== domain) {
      strategies.push(baseDomain);
      strategies.push('.' + baseDomain);
    }
    
    // 5. 对于三级或更多级域名，尝试各级域名
    const parts = domain.split('.');
    if (parts.length > 2) {
      for (let i = 1; i < parts.length - 1; i++) {
        const subDomain = parts.slice(i).join('.');
        if (!strategies.includes(subDomain)) {
          strategies.push(subDomain);
          strategies.push('.' + subDomain);
        }
      }
    }
    
    // 去重并返回
    return [...new Set(strategies)];
  }
  
  // Promise包装的设置Cookie函数
  function setCookiePromise(details) {
    return new Promise((resolve) => {
      try {
        chrome.cookies.set(details, (cookie) => {
          if (chrome.runtime.lastError) {
            console.error('Cookie set error:', chrome.runtime.lastError);
            resolve(false);
          } else {
            resolve(!!cookie);
          }
        });
      } catch (error) {
        console.error('Cookie set exception:', error);
        resolve(false);
      }
    });
  }
  
  // 获取当前标签页信息
  function loadCurrentTabInfo() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].url) {
        try {
          const url = new URL(tabs[0].url);
          
          // 排除浏览器内部页面
          if (url.protocol !== 'chrome:' && url.protocol !== 'edge:' && url.protocol !== 'about:') {
            const protocol = url.protocol;
            const domain = url.hostname;
            
            // 更新域名信息
            currentPageInfo.url = tabs[0].url;
            currentPageInfo.domain = domain;
            currentPageInfo.protocol = protocol;
            currentDomainElement.textContent = domain;
            
            // 为域名添加点击复制功能
            addClickToCopy(currentDomainElement, `${protocol}//${domain}`, '已复制域名到剪贴板');
            
            // 获取User Agent
            chrome.scripting.executeScript({
              target: { tabId: tabs[0].id },
              func: () => { return navigator.userAgent; }
            }).then(results => {
              const userAgent = results && results[0] ? results[0].result : '获取失败';
              currentPageInfo.userAgent = userAgent;
              currentUAElement.textContent = userAgent;
              
              // 为UA添加点击复制功能
              addClickToCopy(currentUAElement, userAgent, '已复制User Agent到剪贴板');
            }).catch(error => {
              console.error("Error getting UserAgent:", error);
              currentUAElement.textContent = "获取失败，请尝试重新打开插件";
            });
            
            // 使用两种方式获取Cookie
            getCookiesFromAPI(domain);
          } else {
            // 浏览器内部页面
            currentDomainElement.textContent = '浏览器内部页面';
            currentUAElement.textContent = '不适用';
            currentCookieElement.textContent = '浏览器内部页面无法获取Cookie';
          }
        } catch (error) {
          console.error("Error parsing URL:", error);
          displayErrorState();
        }
      } else {
        displayErrorState();
      }
    });
  }
  
  // 使用Chrome Cookie API获取Cookie
  function getCookiesFromAPI(domain) {
    // 收集所有可能的Cookie
    let allCookies = [];
    let pendingRequests = 0;
    let requestsCompleted = 0;
    
    // 定义需要查询的域名列表
    const domainsToCheck = [];
    
    // 添加当前完整域名
    domainsToCheck.push(domain);
    
    // 添加基础域名变体
    const baseDomain = getBaseDomain(domain);
    if (baseDomain !== domain) {
      domainsToCheck.push(baseDomain);
      domainsToCheck.push('.' + baseDomain); // 添加点前缀版本
    }
    
    // 添加点前缀的当前域名
    domainsToCheck.push('.' + domain);
    
    // 获取所有子域名级别
    const domainParts = domain.split('.');
    for (let i = 1; i < domainParts.length - 1; i++) {
      const subDomain = domainParts.slice(i).join('.');
      domainsToCheck.push(subDomain);
      domainsToCheck.push('.' + subDomain);
    }
    
    // 去重
    const uniqueDomains = [...new Set(domainsToCheck)];
    pendingRequests = uniqueDomains.length + 1; // +1 for URL-based query
    
    // 完成请求的回调
    const checkCompletion = () => {
      requestsCompleted++;
      if (requestsCompleted === pendingRequests) {
        if (allCookies.length > 0) {
          // 去重并格式化显示
          const uniqueCookies = removeDuplicateCookies(allCookies);
          formatAndDisplayCookies(uniqueCookies);
        } else {
          // 如果还是没有找到Cookie，尝试使用脚本方式获取
          getCookiesFromScript(domain);
        }
      }
    };
    
    // 查询每个域名的Cookie
    uniqueDomains.forEach(d => {
      chrome.cookies.getAll({ domain: d }, (cookies) => {
        if (cookies && cookies.length > 0) {
          allCookies = allCookies.concat(cookies);
        }
        checkCompletion();
      });
    });
    
    // 同时基于URL查询Cookie
    chrome.cookies.getAll({ url: currentPageInfo.url }, (cookies) => {
      if (cookies && cookies.length > 0) {
        allCookies = allCookies.concat(cookies);
      }
      checkCompletion();
    });
  }
  
  // 使用脚本方式获取Cookie (可以获取HttpOnly和某些特殊Cookie)
  function getCookiesFromScript(domain) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].id) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: () => { 
            return {
              cookies: document.cookie, 
              location: window.location.href
            }; 
          }
        }).then(results => {
          if (results && results[0] && results[0].result) {
            const scriptCookies = parseCookieString(results[0].result.cookies);
            if (scriptCookies.length > 0) {
              formatAndDisplayCookies(scriptCookies);
            } else {
              currentCookieElement.textContent = "当前站点没有Cookie";
              currentPageInfo.cookie = '';
            }
          } else {
            currentCookieElement.textContent = "无法获取Cookie";
            currentPageInfo.cookie = '';
          }
        }).catch(error => {
          console.error("Error getting cookies via script:", error);
          currentCookieElement.textContent = "获取Cookie时出错";
          currentPageInfo.cookie = '';
        });
      }
    });
  }
  
  // 解析Cookie字符串为对象数组
  function parseCookieString(cookieStr) {
    if (!cookieStr) return [];
    
    const cookies = [];
    const cookieMap = new Map(); // 用于去重，后面的同名cookie会覆盖前面的
    
    // 支持多种分隔符：分号、换行符
    const cookiePairs = cookieStr.split(/[;\n\r]+/);
    
    cookiePairs.forEach(pair => {
      pair = pair.trim();
      if (!pair) return;
      
      // 支持等号或tab作为分隔符（Chrome开发者工具导出格式）
      const separatorMatch = pair.match(/^([^=\t]+)[=\t](.*)$/);
      if (!separatorMatch) return;
      
      const name = separatorMatch[1].trim();
      let value = separatorMatch[2].trim();
      
      // 移除值两端的引号（如果有）
      if ((value.startsWith('"') && value.endsWith('"')) || 
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      
      // 保留URL编码的值（如 %3D），Chrome会自动处理
      // 只添加有效的Cookie，使用Map去重
      if (name && value !== undefined) {
        cookieMap.set(name, value);
      }
    });
    
    // 将Map转换为数组
    cookieMap.forEach((value, name) => {
      cookies.push({ name, value });
    });
    
    return cookies;
  }
  
  // 格式化并显示Cookie
  function formatAndDisplayCookies(cookies) {
    if (!cookies || cookies.length === 0) {
      currentCookieElement.textContent = "当前站点没有Cookie";
      currentPageInfo.cookie = '';
      return;
    }
    
    // 去重 (可能存在重复Cookie)
    const uniqueCookies = removeDuplicateCookies(cookies);
    
    // 格式化cookie为字符串
    let formattedCookies = '';
    
    // 扩展的优先级分组
    const priorityGroups = {
      // NexusPHP相关 - 最高优先级
      nexusPhp: uniqueCookies.filter(cookie => 
        cookie.name && (
          cookie.name === 'c_secure_uid' ||
          cookie.name === 'c_secure_pass' ||
          cookie.name === 'c_secure_ssl' ||
          cookie.name === 'c_secure_tracker_ssl' ||
          cookie.name === 'c_secure_login' ||
          cookie.name.startsWith('c_secure_')
        )
      ),
      
      // Cloudflare
      cloudflare: uniqueCookies.filter(cookie =>
        cookie.name && (
          cookie.name === 'cf_clearance' ||
          cookie.name.startsWith('__cf') ||
          cookie.name === 'cf_chl_2' ||
          cookie.name === 'cf_chl_prog' ||
          cookie.name.startsWith('cf_')
        )
      ),
      
      // 会话相关
      session: uniqueCookies.filter(cookie =>
        cookie.name && (
          cookie.name === 'sl-session' ||
          cookie.name.toLowerCase().includes('sess') ||
          cookie.name.toLowerCase() === 'phpsessid' ||
          cookie.name.toLowerCase() === 'jsessionid' ||
          cookie.name.toLowerCase() === 'aspsessionid' ||
          cookie.name.toLowerCase().startsWith('asp.net_sessionid')
        )
      ),
      
      // JWT令牌
      jwt: uniqueCookies.filter(cookie =>
        cookie.name && (
          cookie.name.toLowerCase().includes('jwt') ||
          cookie.name.toLowerCase().includes('bearer') ||
          cookie.name.toLowerCase() === 'access_token' ||
          cookie.name.toLowerCase() === 'refresh_token' ||
          cookie.name.toLowerCase() === 'id_token'
        )
      ),
      
      // WordPress相关
      wordpress: uniqueCookies.filter(cookie =>
        cookie.name && (
          cookie.name.startsWith('wordpress_') ||
          cookie.name.startsWith('wp_') ||
          cookie.name === 'wordpress_test_cookie'
        )
      ),
      
      // 其他认证Cookie
      otherAuth: uniqueCookies.filter(cookie => {
        if (!cookie.name) return false;
        
        // 排除已分类的Cookie
        const alreadyClassified = 
          cookie.name.startsWith('c_secure_') ||
          cookie.name.startsWith('cf_') ||
          cookie.name === 'cf_clearance' ||
          cookie.name.startsWith('__cf') ||
          cookie.name === 'sl-session' ||
          cookie.name.toLowerCase().includes('sess') ||
          cookie.name.toLowerCase().includes('jwt') ||
          cookie.name.toLowerCase().includes('bearer') ||
          cookie.name.toLowerCase() === 'access_token' ||
          cookie.name.toLowerCase() === 'refresh_token' ||
          cookie.name.startsWith('wordpress_') ||
          cookie.name.startsWith('wp_');
        
        return !alreadyClassified && isLikelyAuthCookie(cookie.name);
      }),
      
      // 分析和追踪Cookie（低优先级）
      analytics: uniqueCookies.filter(cookie =>
        cookie.name && (
          cookie.name.startsWith('_ga') ||
          cookie.name.startsWith('_gid') ||
          cookie.name === '_gat' ||
          cookie.name.startsWith('_utm') ||
          cookie.name === '_fbp' ||
          cookie.name.startsWith('_hjid')
        )
      )
    };
    
    // 剩余的Cookie
    const classifiedCookieNames = new Set();
    Object.values(priorityGroups).flat().forEach(cookie => {
      if (cookie.name) classifiedCookieNames.add(cookie.name);
    });
    
    const remainingCookies = uniqueCookies.filter(cookie => 
      cookie.name && !classifiedCookieNames.has(cookie.name) && 
      !priorityGroups.analytics.some(c => c.name === cookie.name)
    );
    
    // 按优先级排序合并
    const sortedCookies = [
      ...priorityGroups.nexusPhp,
      ...priorityGroups.cloudflare,
      ...priorityGroups.session,
      ...priorityGroups.jwt,
      ...priorityGroups.wordpress,
      ...priorityGroups.otherAuth,
      ...remainingCookies,
      ...priorityGroups.analytics  // 分析Cookie放最后
    ];
    
    // 生成格式化的Cookie字符串
    sortedCookies.forEach(cookie => {
      if (cookie.name && cookie.value !== undefined) {
        formattedCookies += `${cookie.name}=${cookie.value}; `;
      }
    });
    
    // 去除末尾的分号和空格
    formattedCookies = formattedCookies.replace(/;\s*$/, '');
    
    currentPageInfo.cookie = formattedCookies;
    currentCookieElement.textContent = formattedCookies;
    
    // 为Cookie添加点击复制功能
    addClickToCopy(currentCookieElement, formattedCookies, '已复制Cookie到剪贴板');
  }
  
  // 判断是否可能是认证Cookie
  function isLikelyAuthCookie(name) {
    if (!name) return false;
    
    const authKeywords = [
      // 认证相关
      'auth', 'authentication', 'authorize', 'authorization',
      'token', 'access', 'refresh', 'bearer',
      'session', 'sess', 'sid', 'sessionid',
      'user', 'userid', 'user_id', 'username',
      'login', 'logged', 'loggedin', 'signin',
      'pass', 'password', 'passwd',
      'uid', 'uuid', 'guid',
      'id', 'identifier',
      'remember', 'remember_me', 'keep_me',
      'secure', 'security',
      'csrf', 'xsrf', '_csrf', 'csrftoken',
      'key', 'apikey', 'api_key', 'appkey',
      'hash', 'signature', 'sig',
      'account', 'profile',
      'member', 'membership',
      'identity', 'ident',
      'credential', 'cred',
      
      // OAuth相关
      'oauth', 'openid', 'oidc',
      'state', 'nonce', 'code_verifier',
      
      // 特定平台
      'connect.sid', // Express.js
      'laravel_session', // Laravel
      'ci_session', // CodeIgniter
      'symfony', // Symfony
      'rails_session', // Ruby on Rails
      
      // 追踪和验证
      'tracker', 'tracking',
      'passkey', 'secret',
      'verify', 'verification', 'verified',
      'confirm', 'confirmation',
      'ticket', 'tkt',
      
      // 其他常见模式
      'sso', 'saml',
      'jwt', 'jti',
      'device', 'deviceid',
      'client', 'clientid',
      'grant', 'scope',
      'principal', 'subject'
    ];
    
    const lowercaseName = name.toLowerCase();
    
    // 检查是否包含任何关键词
    const hasKeyword = authKeywords.some(keyword => lowercaseName.includes(keyword));
    
    // 检查特定模式
    const hasAuthPattern = 
      // Base64编码的值（可能是令牌）
      /^[a-zA-Z0-9_-]{20,}$/.test(name) ||
      // UUID格式
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(name) ||
      // 看起来像会话ID的模式
      /^[a-zA-Z0-9]{16,}$/.test(name) ||
      // 包含下划线的认证相关名称
      /_(?:id|token|key|session|auth|user)$/i.test(name) ||
      /^(?:id|token|key|session|auth|user)_/i.test(name);
    
    return hasKeyword || hasAuthPattern;
  }
  
  // 去除重复Cookie (以name为唯一键)
  function removeDuplicateCookies(cookies) {
    const uniqueCookies = {};
    cookies.forEach(cookie => {
      if (cookie.name) {
        uniqueCookies[cookie.name] = cookie;
      }
    });
    return Object.values(uniqueCookies);
  }
  
  // 从域名中提取基础域名 (如 sub.example.com -> example.com)
  function getBaseDomain(domain) {
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;
    
    // 扩展的特殊二级域名列表
    const specialTLDs = [
      // 国家代码二级域名
      'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk', 'me.uk',
      'com.cn', 'org.cn', 'net.cn', 'ac.cn', 'edu.cn', 'gov.cn',
      'com.au', 'org.au', 'net.au', 'edu.au', 'gov.au',
      'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
      'co.kr', 'or.kr', 'ne.kr', 'ac.kr', 'go.kr',
      'com.br', 'org.br', 'net.br', 'edu.br', 'gov.br',
      'com.tw', 'org.tw', 'net.tw', 'edu.tw', 'gov.tw',
      'co.in', 'org.in', 'net.in', 'edu.in', 'gov.in',
      'co.nz', 'org.nz', 'net.nz', 'edu.nz', 'govt.nz',
      'co.za', 'org.za', 'net.za', 'edu.za', 'gov.za',
      'com.sg', 'org.sg', 'net.sg', 'edu.sg', 'gov.sg',
      'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk',
      'com.mx', 'org.mx', 'net.mx', 'edu.mx', 'gob.mx',
      
      // 其他常见的二级域名
      'co.id', 'or.id', 'ac.id', 'go.id',
      'com.my', 'org.my', 'net.my', 'edu.my', 'gov.my',
      'com.ph', 'org.ph', 'net.ph', 'edu.ph', 'gov.ph',
      'com.vn', 'org.vn', 'net.vn', 'edu.vn', 'gov.vn',
      'com.ar', 'org.ar', 'net.ar', 'edu.ar', 'gov.ar',
      'com.co', 'org.co', 'net.co', 'edu.co', 'gov.co',
      'com.pe', 'org.pe', 'net.pe', 'edu.pe', 'gob.pe',
      'com.ve', 'org.ve', 'net.ve', 'edu.ve', 'gob.ve',
      'com.eg', 'org.eg', 'net.eg', 'edu.eg', 'gov.eg',
      'com.tr', 'org.tr', 'net.tr', 'edu.tr', 'gov.tr',
      'com.pk', 'org.pk', 'net.pk', 'edu.pk', 'gov.pk',
      'com.sa', 'org.sa', 'net.sa', 'edu.sa', 'gov.sa',
      'com.ua', 'org.ua', 'net.ua', 'edu.ua', 'gov.ua',
      'com.ru', 'org.ru', 'net.ru', 'edu.ru', 'gov.ru',
      'com.pl', 'org.pl', 'net.pl', 'edu.pl', 'gov.pl',
      'co.th', 'or.th', 'ac.th', 'go.th', 'net.th'
    ];
    
    const domainSuffix = parts.slice(-2).join('.');
    
    if (specialTLDs.includes(domainSuffix)) {
      if (parts.length <= 3) return domain;
      return parts.slice(-3).join('.');
    }
    
    return parts.slice(-2).join('.');
  }
  
  // 显示错误状态
  function displayErrorState() {
    currentDomainElement.textContent = '无法获取当前域名';
    currentUAElement.textContent = '无法获取User Agent';
    currentCookieElement.textContent = '无法获取Cookie';
    currentPageInfo = {
      url: '',
      domain: '',
      userAgent: '',
      protocol: '',
      cookie: ''
    };
  }
  
  // 为元素添加点击复制功能
  function addClickToCopy(element, text, successMessage) {
    element.style.cursor = 'pointer';
    element.onclick = () => {
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          showCopyNotice(successMessage);
        });
      }
    };
  }
  
  // 显示状态消息
  function showStatus(message, type) {
    statusElement.textContent = message;
    statusElement.className = 'status ' + type;
    statusElement.style.display = 'block';
    
    // 3秒后隐藏状态消息
    setTimeout(() => {
      statusElement.style.display = 'none';
    }, 3000);
  }
  
  // 显示复制成功提示
  function showCopyNotice(message) {
    copyNotice.textContent = message;
    copyNotice.style.display = 'block';
    setTimeout(() => {
      copyNotice.style.display = 'none';
    }, 2000);
  }
});