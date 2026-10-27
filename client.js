/**
 * 系统守护 · 主面板（Client 半边）。
 *
 * 注册两处：
 *   1. `sidebar.panellist`：id `system-guard`、order 20 的侧栏入口（盾牌图标，props `{ size, active }`）；
 *   2. `main`：key `system-guard` 的整页面板。
 *
 * 数据全部走 Host 注册的同源 HTTP 接口（CONTRACT §6，以 Lead 的细化约定为准）：
 *   GET  /dsh-system-guard/api/state     轻量状态（settings / privilege / schedule / probe / backup / lastPatrol / lastCalibration / baseline / tasks / policy / selfCheck / pendingCalibrationAsk）
 *   GET  /dsh-system-guard/api/analysis  分析明细（analysis.files + junk.groups，首次加载与分析/垃圾扫描完成后拉取）
 *   POST /dsh-system-guard/api/action    { action, payload }；短操作直接回 { ok, value }，长操作回 { ok, taskId }
 *   GET  /dsh-system-guard/api/task?id=  长任务轮询（每 1.5s；done / failed 后刷新 state + analysis）
 *
 * 样式只用宿主主题 token（--dsw-alias-* / --dsw-radius-*），不引宿主组件库、不读宿主 DOM、
 * 不往 document.body 追加任何节点。界面文案为简体中文。
 */
window.__ModuleLoader__.load({
  id: 'dsh-system-guard',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useCallback, useEffect, useMemo, useState } = React

    /** 主面板 key / 侧栏面板 id，两处必须一致。 */
    const PANEL_ID = 'system-guard'
    /** 插件 HTTP 前缀。 */
    const API = '/dsh-system-guard/api'
    /** 长任务轮询间隔。 */
    const POLL_MS = 1500
    /** 长清单最多渲染多少条。 */
    const LIST_LIMIT = 300

    /** 权限边界文案：底层逻辑，不可修改（与 lib/privilege.js 一致）。 */
    const CHARTER_TEXT = '守护权限只用于保护系统，无法用于保护系统以外的事情（底层逻辑，不可修改）'

    const KIND_LABEL = {
      analyze: '分析',
      patrol: '巡查',
      backup: '备份',
      repair: '修复',
      'junk-scan': '垃圾扫描',
      'junk-delete': '删除垃圾',
      calibrate: '联网校准',
      'restore-point': '创建还原点',
    }

    const VERDICT_INFO = {
      healthy: { text: '健康', tone: 'success' },
      changed: { text: '有变化', tone: 'warn' },
      damaged: { text: '已损坏', tone: 'error' },
      unknown: { text: '无法判断', tone: 'muted' },
    }

    /** 错误码 → 可执行的中文提示。 */
    const ERROR_HINTS = {
      'need-elevation': '需要管理员权限，请先点「授予守护权限」。',
      'confirm-required': '这个操作需要二次确认，请重新执行并确认。',
      'no-baseline': '还没有核心文件基线，请先点「分析」。',
      'self-check-failed': '插件核心代码自校验失败，为安全起见已拒绝写操作；请重新安装插件。',
      'elevation-cancelled': '你取消了 UAC 授权请求，守护权限未获得。',
    }

    const TONE_COLOR = {
      success: 'var(--dsw-alias-state-success-primary)',
      warn: 'var(--dsw-alias-state-warn-primary)',
      error: 'var(--dsw-alias-state-error-primary)',
      muted: 'var(--dsw-alias-label-secondary)',
    }

    // ============================================================
    // 样式：只用主题 token，卡片 / 圆角 / 间距对齐宿主设置页
    // ============================================================
    const S = {
      // 面板骨架：宿主 main 区是 flex 列，这里撑满并自己管滚动。
      panel: {
        height: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        minHeight: 0,
        background: 'var(--dsw-alias-bg-base)',
        color: 'var(--dsw-alias-label-primary)',
      },
      scroller: {
        flex: '1 1 auto',
        minHeight: 0,
        overflowY: 'auto',
        overflowX: 'hidden',
        boxSizing: 'border-box',
        paddingTop: 'calc(28px + var(--dsh-frame-top-clearance, 0px))',
        paddingBottom: '64px',
        paddingLeft: 'max(clamp(16px, 4vw, 48px), calc((100% - 960px) / 2))',
        paddingRight: 'max(clamp(16px, 4vw, 48px), calc((100% - 960px) / 2))',
      },
      stack: {
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
        width: '100%',
        maxWidth: '960px',
        margin: '0 auto',
        fontSize: '13px',
        lineHeight: '1.6',
      },
      header: {
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: '16px',
        flexWrap: 'wrap',
      },
      headerText: { display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 },
      title: { fontSize: '20px', fontWeight: 600, margin: 0, lineHeight: '1.4' },
      subtitle: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      body: { fontSize: '12px', margin: 0 },
      card: {
        background: 'var(--dsw-alias-bg-layer-1)',
        // 黑色边框：浅色主题是黑框、深色主题自动变成白框（同一个 token，跟随模式）。
        border: '1.5px solid var(--dsw-alias-label-primary)',
        borderRadius: '12px',
        padding: '16px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      },
      cardHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' },
      cardTitle: { fontSize: '14px', fontWeight: 600, margin: 0 },
      cardExtra: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px' },
      hint: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      tiny: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      kv: { display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '12px', alignItems: 'baseline' },
      kvKey: { color: 'var(--dsw-alias-label-secondary)' },
      kvValue: { minWidth: 0, wordBreak: 'break-word' },
      charter: {
        margin: 0,
        fontSize: '13px',
        fontWeight: 600,
        color: 'var(--dsw-alias-state-warn-label)',
        border: '1px solid var(--dsw-alias-state-warn-primary)',
        borderRadius: '10px',
        padding: '10px 12px',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      row: { display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' },
      rowBetween: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' },
      button: {
        // 主操作按钮：黑底反白，比品牌色更沉稳、更醒目。
        background: 'var(--dsw-alias-label-primary)',
        color: 'var(--dsw-alias-bg-base)',
        border: 'none',
        borderRadius: '8px',
        padding: '9px 18px',
        fontSize: '14px',
        fontWeight: 600,
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonSecondary: {
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-label-primary)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '6px 14px',
        fontSize: '12px',
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonDanger: {
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-state-error-primary)',
        border: '1px solid var(--dsw-alias-state-error-primary)',
        borderRadius: '8px',
        padding: '6px 14px',
        fontSize: '12px',
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonDangerSolid: {
        background: 'var(--dsw-alias-state-error-primary)',
        color: '#ffffff',
        border: 'none',
        borderRadius: '8px',
        padding: '9px 18px',
        fontSize: '14px',
        fontWeight: 600,
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonDisabled: { opacity: 0.5, cursor: 'default' },
      linkButton: {
        background: 'transparent',
        border: 'none',
        padding: '0 2px',
        color: 'var(--dsw-alias-brand-primary)',
        fontSize: '12px',
        cursor: 'pointer',
        fontFamily: 'inherit',
      },
      input: {
        width: '110px',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-bg-base)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '6px 10px',
        color: 'var(--dsw-alias-label-primary)',
        fontSize: '13px',
        fontFamily: 'inherit',
      },
      tileGrid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gridAutoRows: '1fr',
        gap: '12px',
      },
      // 分区标题：把面板切成「概览 / 常用操作 / 清理与备份 / 联网校准 / 巡查结果 / 诊断」几段。
      sectionBar: { display: 'flex', alignItems: 'center', gap: '10px', marginTop: '4px' },
      sectionLabel: {
        flex: 'none',
        fontSize: '12px',
        fontWeight: 700,
        letterSpacing: '0.08em',
        color: 'var(--dsw-alias-label-secondary)',
      },
      sectionLine: { height: '1px', flex: '1 1 auto', background: 'var(--dsw-alias-border-l1)' },
      // 四个动作框统一主色实心（浅色主题黑 / 深色主题白），右上角小点标危险等级。
      tileSolid: {
        position: 'relative',
        textAlign: 'left',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        gap: '3px',
        minHeight: '84px',
        height: '100%',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-label-primary)',
        border: 'none',
        borderRadius: '10px',
        padding: '12px 16px',
        color: 'var(--dsw-alias-bg-base)',
        fontFamily: 'inherit',
        cursor: 'pointer',
        fontSize: '15px',
        fontWeight: 700,
        lineHeight: '1.4',
      },
      // 下面三套保留给其它样式引用（当前动作框统一用 tileSolid）。
      // 统一高度 + 文字单行省略，保证四个框大小完全一致。
      tile: {
        textAlign: 'left',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        gap: '3px',
        minHeight: '84px',
        height: '100%',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-bg-layer-1)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '10px',
        padding: '12px 16px',
        color: 'var(--dsw-alias-label-primary)',
        fontFamily: 'inherit',
        cursor: 'pointer',
        fontSize: '15px',
        fontWeight: 700,
        lineHeight: '1.4',
      },
      tilePrimary: {
        textAlign: 'left',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        gap: '3px',
        minHeight: '84px',
        height: '100%',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-label-primary)',
        border: '1px solid transparent',
        borderRadius: '10px',
        padding: '12px 16px',
        color: 'var(--dsw-alias-bg-base)',
        fontFamily: 'inherit',
        cursor: 'pointer',
        fontSize: '15px',
        fontWeight: 700,
        lineHeight: '1.4',
      },
      tileDanger: {
        textAlign: 'left',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        gap: '3px',
        minHeight: '84px',
        height: '100%',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-state-error-primary)',
        border: '1px solid transparent',
        borderRadius: '10px',
        padding: '12px 16px',
        color: '#ffffff',
        fontFamily: 'inherit',
        cursor: 'pointer',
        fontSize: '15px',
        fontWeight: 700,
        lineHeight: '1.4',
      },
      tileHint: {
        color: 'var(--dsw-alias-label-secondary)',
        fontSize: '12px',
        fontWeight: 400,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      },
      tileHintOnDark: {
        color: 'var(--dsw-alias-bg-base)',
        opacity: 0.72,
        fontSize: '12px',
        fontWeight: 400,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      },
      tileHintDanger: {
        color: '#ffffff',
        opacity: 0.82,
        fontSize: '12px',
        fontWeight: 400,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      },
      progressTrack: {
        height: '6px',
        borderRadius: '999px',
        background: 'var(--dsw-alias-bg-layer-2)',
        overflow: 'hidden',
      },
      progressFill: {
        height: '100%',
        borderRadius: '999px',
        background: 'var(--dsw-alias-brand-primary)',
        transition: 'width 240ms ease',
      },
      error: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px', margin: 0 },
      ok: { color: 'var(--dsw-alias-state-success-primary)', fontSize: '12px', margin: 0 },
      warn: { color: 'var(--dsw-alias-state-warn-primary)', fontSize: '12px', margin: 0 },
      banner: {
        display: 'flex',
        alignItems: 'flex-start',
        gap: '8px',
        borderRadius: '10px',
        padding: '10px 12px',
        fontSize: '12px',
        border: '1px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      bannerError: {
        borderColor: 'var(--dsw-alias-state-error-primary)',
        color: 'var(--dsw-alias-state-error-primary)',
      },
      bannerOk: {
        borderColor: 'var(--dsw-alias-state-success-primary)',
        color: 'var(--dsw-alias-state-success-primary)',
      },
      badge: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '1px 9px',
        borderRadius: '999px',
        fontSize: '12px',
        fontWeight: 600,
        border: '1px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      groupCard: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '10px',
        padding: '8px 12px',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      groupHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' },
      // 折叠态整行可点：一行放下「分类名 + 大小/项数 + 展开」，不再每组占三行。
      groupHeadButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        width: '100%',
        boxSizing: 'border-box',
        background: 'transparent',
        border: 'none',
        padding: 0,
        margin: 0,
        cursor: 'pointer',
        color: 'var(--dsw-alias-label-primary)',
        font: 'inherit',
        textAlign: 'left',
      },
      groupHeadText: { display: 'flex', alignItems: 'baseline', gap: '10px', flex: '1 1 auto', minWidth: 0 },
      groupTitle: { fontSize: '13px', fontWeight: 600, flex: 'none' },
      groupMeta: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', flex: 'none' },
      groupBody: { display: 'flex', flexDirection: 'column', gap: '8px' },
      items: {
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        maxHeight: '360px',
        overflowY: 'auto',
        overflowX: 'hidden',
        paddingRight: '4px',
      },
      itemRow: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '12px',
        color: 'var(--dsw-alias-label-secondary)',
        cursor: 'pointer',
      },
      itemPath: { minWidth: 0, flex: '1 1 auto', wordBreak: 'break-all' },
      itemSize: { flex: 'none', color: 'var(--dsw-alias-label-secondary)' },
      checkbox: {
        flex: 'none',
        width: '14px',
        height: '14px',
        margin: 0,
        accentColor: 'var(--dsw-alias-brand-primary)',
      },
      deleteBar: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        flexWrap: 'wrap',
        borderTop: '1px solid var(--dsw-alias-border-l2)',
        paddingTop: '12px',
      },
      confirmBar: {
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        flexWrap: 'wrap',
        border: '1px solid var(--dsw-alias-state-error-primary)',
        borderRadius: '10px',
        padding: '10px 12px',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      confirmText: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px', margin: 0 },
      list: { display: 'flex', flexDirection: 'column', gap: '6px', margin: 0, padding: 0, listStyle: 'none' },
      listItem: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-all', margin: 0 },
      link: { color: 'var(--dsw-alias-brand-primary)', textDecoration: 'none', wordBreak: 'break-all' },
      mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '11px' },
      settingsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' },
      field: { display: 'flex', flexDirection: 'column', gap: '6px' },
      fieldLabel: { fontSize: '12px', fontWeight: 500 },
      divider: { height: '1px', background: 'var(--dsw-alias-border-l1)', border: 'none', margin: 0 },
      sectionTitle: { fontSize: '12px', fontWeight: 600, color: 'var(--dsw-alias-label-secondary)', margin: 0 },
      // 可折叠标题行：看起来像普通小标题，但整行可点，右侧带「展开/收起」。
      collapsibleHead: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '8px',
        width: '100%',
        boxSizing: 'border-box',
        background: 'transparent',
        border: 'none',
        padding: 0,
        margin: 0,
        cursor: 'pointer',
        color: 'var(--dsw-alias-label-primary)',
        font: 'inherit',
        textAlign: 'left',
      },
      // 更醒目的折叠条（整卡折叠用）：浅底 + 边框 + 品牌色按钮，避免被当成普通说明文字忽略。
      collapseBar: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        width: '100%',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-bg-layer-1)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '9px 12px',
        margin: 0,
        cursor: 'pointer',
        color: 'var(--dsw-alias-label-primary)',
        font: 'inherit',
        fontSize: '13px',
        textAlign: 'left',
      },
      collapseBarText: { display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: '1 1 auto' },
      collapseBarCaret: { flex: 'none', color: 'var(--dsw-alias-brand-primary)', fontWeight: 700 },
      collapseBarAction: {
        flex: 'none',
        color: 'var(--dsw-alias-brand-primary)',
        border: '1px solid var(--dsw-alias-brand-primary)',
        borderRadius: '6px',
        padding: '2px 10px',
        fontSize: '12px',
        fontWeight: 600,
        background: 'transparent',
      },
      empty: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
    }

    // ============================================================
    // 纯函数工具
    // ============================================================
    function isObj(value) {
      return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    }

    function arr(value) {
      return Array.isArray(value) ? value : []
    }

    function num(value) {
      const n = Number(value)
      return Number.isFinite(n) ? n : 0
    }

    function text(value, fallback) {
      if (typeof value === 'string') return value.trim() ? value : (fallback === undefined ? '' : fallback)
      if (typeof value === 'number' && Number.isFinite(value)) return String(value)
      return fallback === undefined ? '' : fallback
    }

    /** 截断超长文本（例如校准限制里带的原始英文错误）；完整内容放 title 里悬停看。 */
    function clipText(value, max = 260) {
      const raw = String(value === undefined || value === null ? '' : value)
      return raw.length > max ? `${raw.slice(0, max)}…` : raw
    }

    function messageOf(error) {
      if (!error) return '操作失败。'
      if (typeof error === 'string') return error
      if (typeof error.message === 'string' && error.message.trim()) return error.message
      return '操作失败。'
    }

    function clamp(n, min, max) {
      return Math.min(max, Math.max(min, n))
    }

    function clampInt(value, min, max, fallback) {
      if (typeof value === 'string' && value.trim() === '') return fallback
      if (value === null || value === undefined || value === '') return fallback
      const n = Number(value)
      if (!Number.isFinite(n)) return fallback
      return clamp(Math.round(n), min, max)
    }

    /** 数字型设置的安全回显：缺失/坏值一律回落到默认值。 */
    function numberOrDefault(value, fallback) {
      if (value === null || value === undefined || value === '') return fallback
      return Number.isFinite(Number(value)) ? value : fallback
    }

    function firstTimestamp(values) {
      for (const value of arr(values)) {
        const n = Number(value)
        if (Number.isFinite(n) && n > 0) return n
      }
      return null
    }

    function formatBytes(bytes) {
      const n = Number(bytes)
      if (!Number.isFinite(n) || n <= 0) return '0 KB'
      const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
      let value = n
      let index = 0
      while (value >= 1024 && index < units.length - 1) {
        value /= 1024
        index += 1
      }
      const digits = index === 0 ? 0 : value >= 100 ? 0 : 1
      return `${value.toFixed(digits)} ${units[index]}`
    }

    function formatTime(timestamp) {
      const n = Number(timestamp)
      if (!Number.isFinite(n) || n <= 0) return '从未'
      try {
        return new Date(n).toLocaleString('zh-CN', { hour12: false })
      } catch (error) {
        return '时间未知'
      }
    }

    function formatDuration(ms) {
      const n = Number(ms)
      if (!Number.isFinite(n) || n < 0) return ''
      if (n < 1000) return `${Math.round(n)} 毫秒`
      if (n < 60000) return `${(n / 1000).toFixed(1)} 秒`
      return `${Math.round(n / 60000)} 分钟`
    }

    function shortSha(sha) {
      const value = text(sha)
      return value ? value.slice(0, 12) : '—'
    }

    function verdictInfo(verdict) {
      return VERDICT_INFO[text(verdict)] || VERDICT_INFO.unknown
    }

    function findingTone(level) {
      const key = text(level).toLowerCase()
      if (key === 'error' || key === 'critical' || key === 'danger') return 'error'
      if (key === 'warn' || key === 'warning') return 'warn'
      if (key === 'ok' || key === 'success' || key === 'good') return 'success'
      return 'muted'
    }

    function progressPercent(value) {
      if (isObj(value)) {
        if (Number.isFinite(Number(value.percent))) return clamp(Number(value.percent), 0, 100)
        const done = Number(value.done)
        const total = Number(value.total)
        if (Number.isFinite(done) && Number.isFinite(total) && total > 0) {
          return clamp((done / total) * 100, 0, 100)
        }
        return null
      }
      const n = Number(value)
      if (!Number.isFinite(n)) return null
      return clamp(n <= 1 ? n * 100 : n, 0, 100)
    }

    function unwrapValue(result) {
      if (isObj(result) && result.value !== undefined) return result.value
      return result
    }

    function readError(payload, status) {
      const data = isObj(payload) ? payload : {}
      const error = isObj(data.error) ? data.error : null
      const code = error ? text(error.code) : ''
      const message = error ? text(error.message) : ''
      if (message) return message
      if (code && ERROR_HINTS[code]) return ERROR_HINTS[code]
      if (status === 404) return '插件接口不存在（HTTP 404），插件可能未启用或版本过旧。'
      if (status === 401 || status === 403) return `没有访问插件接口的权限（HTTP ${status}）。`
      if (typeof data.message === 'string' && data.message.trim()) return data.message
      return status ? `插件接口返回失败（HTTP ${status}）。` : '插件接口返回失败。'
    }

    async function requestJson(url, init) {
      let response
      try {
        response = await fetch(url, init || {})
      } catch (error) {
        throw new Error(`无法连接插件接口：${messageOf(error)}`)
      }
      let payload = null
      try {
        payload = await response.json()
      } catch (error) {
        throw new Error(`插件接口返回了无法解析的内容（HTTP ${response.status}）。`)
      }
      if (!isObj(payload)) {
        throw new Error(`插件接口返回为空（HTTP ${response.status}）。`)
      }
      if (payload.ok === false || !response.ok) {
        throw new Error(readError(payload, response.status))
      }
      return payload
    }

    function getJson(path) {
      return requestJson(API + path, { headers: { accept: 'application/json' } })
    }

    function postAction(action, payload) {
      return requestJson(API + '/action', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ action, payload: payload === undefined ? null : payload }),
      })
    }

    // ============================================================
    // 数据形状兜底（Host 字段缺失时不至于让面板崩掉）
    // ============================================================
    function normalizeState(payload) {
      const data = isObj(payload) ? payload : {}
      const schedule = isObj(data.schedule) ? data.schedule : {}
      const probe = isObj(data.probe) ? data.probe : null
      const privilege = isObj(data.privilege) ? data.privilege : {}
      return {
        settings: isObj(data.settings) ? data.settings : {},
        privilege,
        schedule,
        probe,
        backup: isObj(data.backup) ? data.backup : null,
        lastPatrol: isObj(data.lastPatrol) ? data.lastPatrol : null,
        lastCalibration: isObj(data.lastCalibration)
          ? data.lastCalibration
          : isObj(data.lastCalibrate) ? data.lastCalibrate : null,
        baseline: isObj(data.baseline) ? data.baseline : {},
        tasks: arr(data.tasks),
        policy: isObj(data.policy) ? data.policy : {},
        selfCheck: isObj(data.selfCheck) ? data.selfCheck : null,
        pendingCalibrationAsk:
          data.pendingCalibrationAsk === true
          || (isObj(data.pendingCalibrationAsk) && data.pendingCalibrationAsk.pending === true),
        nextCalibrateAskAt: firstTimestamp([
          data.nextCalibrateAskAt,
          schedule.nextCalibrateAskAt,
          schedule.nextCalibrationAt,
          schedule.nextCalibrateAt,
        ]),
        /** 插件版本与平台：只用于展示，方便别人反馈问题时说清楚环境。 */
        version: text(data.version),
        platform: text(data.platform) || (probe ? text(probe.platform) : ''),
        admin: (probe && probe.admin === true) || privilege.granted === true,
      }
    }

    function normalizeDetail(payload) {
      const data = isObj(payload) ? payload : {}
      const analysis = isObj(data.analysis) ? data.analysis : null
      const junk = isObj(data.junk) ? data.junk : null
      const rawGroups = arr(junk && junk.groups).length ? arr(junk.groups) : arr(analysis && analysis.groups)
      const groups = rawGroups.filter(isObj)
      return {
        analysis,
        probe: isObj(data.probe) ? data.probe : null,
        backup: isObj(data.backup) ? data.backup : null,
        junkGroups: groups.filter((group) => text(group.kind) !== 'memory'),
        memoryGroups: groups.filter((group) => text(group.kind) === 'memory'),
        junkTotalBytes: num(junk && junk.totalBytes) || num(analysis && analysis.totalJunkBytes),
        warnings: arr(junk && junk.warnings).concat(arr(analysis && analysis.warnings)),
      }
    }

    function collectSelectedItems(groups, selection) {
      const picked = []
      for (const group of arr(groups)) {
        if (!isObj(group)) continue
        const groupId = text(group.id)
        for (const item of arr(group.items)) {
          if (!isObj(item) || typeof item.path !== 'string' || !item.path) continue
          if (selection[`${groupId}|${item.path}`] === true) {
            picked.push({ path: item.path, size: num(item.size) })
          }
        }
      }
      return picked
    }

    function collectRepairPaths(state) {
      if (!state || !isObj(state.lastPatrol)) return []
      const report = state.lastPatrol
      const paths = []
      for (const missing of arr(report.missing)) {
        const path = typeof missing === 'string' ? missing.trim() : ''
        if (path) paths.push(path)
      }
      for (const change of arr(report.changed)) {
        if (!isObj(change) || change.exempted === true) continue
        const path = text(change.path).trim()
        if (path) paths.push(path)
      }
      const seen = new Set()
      return paths.filter((path) => {
        if (seen.has(path)) return false
        seen.add(path)
        return true
      })
    }

    function sumGroupBytes(groups) {
      return arr(groups).reduce((sum, group) => sum + (isObj(group) ? num(group.totalBytes) : 0), 0)
    }

    function sumGroupCount(groups) {
      return arr(groups).reduce((sum, group) => {
        if (!isObj(group)) return sum
        return sum + Math.max(num(group.itemCount), arr(group.items).length)
      }, 0)
    }

    function describeVolume(volume) {
      if (!isObj(volume)) return '未知'
      const id = text(volume.id, '?')
      const label = text(volume.label)
      const fs = text(volume.fs)
      const head = `${id}${label ? ` ${label}` : ''}${fs ? ` · ${fs}` : ''}`
      return `${head} · 空闲 ${formatBytes(num(volume.freeBytes))} / 共 ${formatBytes(num(volume.totalBytes))}`
    }

    function summarizeResult(kind, value) {
      const v = isObj(value) ? value : {}
      switch (text(kind)) {
        case 'analyze':
          return `分析完成：核心文件 ${num(v.coreCount)} 个、系统文件 ${num(v.supportCount)} 个，垃圾合计 ${formatBytes(num(v.totalJunkBytes))}。`
        case 'patrol':
          return `巡查完成：${verdictInfo(v.verdict).text}。`
        case 'backup':
          return `备份完成：${num(v.fileCount)} 个文件，共 ${formatBytes(num(v.totalBytes))}。`
        case 'repair': {
          // core 返回 {ok:true, repair:{actions,...}}；直接把嵌套层解出来，别显示成 0/0。
          const report = isObj(v.repair) ? v.repair : v
          const actions = arr(report.actions)
          const done = actions.filter((action) => isObj(action) && action.ok === true).length
          if (report.ok === false) {
            return text(report.error && report.error.message) || text(report.output) || '修复未完成。'
          }
          return `修复完成：${done}/${actions.length} 个步骤成功。`
        }
        case 'junk-scan':
          return `垃圾扫描完成：合计 ${formatBytes(num(v.totalBytes))}。`
        case 'calibrate':
          if (v.ok === false) return '联网校准失败。'
          return `联网校准完成${text(v.summary) ? `：${text(v.summary)}` : '。'}`
        case 'restore-point': {
          // core 返回 {ok:true, result:{ok,message,restorePointAt}}。
          const inner = isObj(v.result) ? v.result : v
          if (inner.ok === false || v.ok === false) {
            return text(inner.message) || '系统还原点未创建。'
          }
          const at = num(inner.restorePointAt)
          if (at > 0) return `已创建系统还原点「dsh-system-guard」（${formatTime(at)}）。`
          return text(inner.message) || '系统还原点创建完成。'
        }
        default:
          return '操作完成。'
      }
    }

    // ============================================================
    // 展示组件
    // ============================================================
    function Badge(props) {
      const color = TONE_COLOR[props.tone] || TONE_COLOR.muted
      return h('span', { style: { ...S.badge, color, borderColor: color } }, props.children)
    }

    /**
     * 动作圆点：整卡的操作用右上角不同颜色的点表示。
     *   重要动作 = 黑点（label-primary）
     *   危险动作 = 红点（state-error-primary）
     *   次要动作 = 灰点（border-l2，描边）
     * 悬停显示动作名；未授权 / 忙碌时半透明且不可点。
     */
    const DOT_COLOR = {
      primary: 'var(--dsw-alias-label-primary)',
      danger: 'var(--dsw-alias-state-error-primary)',
    }

    /**
     * 三种点的形状与颜色，全部走主题 token，所以切换深浅主题会自动反转：
     *   重要 = 实心主色（浅色主题黑点 / 深色主题白点）
     *   危险 = 实心红（两种主题都是红）
     *   次要 = 空心灰圈（浅色主题深灰描边 / 深色主题浅灰描边）
     * 再给点加一圈与卡片底色同色的细环，保证贴在卡片上有清晰轮廓。
     */
    function dotStyle(tone) {
      const isSecondary = tone === 'secondary'
      return {
        flex: 'none',
        width: '14px',
        height: '14px',
        boxSizing: 'border-box',
        borderRadius: '50%',
        padding: 0,
        background: isSecondary ? 'transparent' : DOT_COLOR[tone],
        border: isSecondary ? '2px solid var(--dsw-alias-label-secondary)' : 'none',
        boxShadow: '0 0 0 2px var(--dsw-alias-bg-layer-1)',
      }
    }

    /**
     * 卡片右上角的小圆点：只做信息标识（不承担操作）。
     * 重要 = 实心主色（浅色主题黑 / 深色主题白）、危险 = 实心红、次要 = 空心灰圈。
     * 鼠标悬停时弹出气泡，说明这个点的危险分级。
     */
    function DotInfo(props) {
      const [hover, setHover] = useState(false)
      const tone = props.tone === 'primary' ? 'primary' : props.tone === 'danger' ? 'danger' : 'secondary'
      const label = props.title || ''
      return h('span', {
        style: { position: 'relative', display: 'inline-flex', alignItems: 'center' },
        onMouseEnter: () => setHover(true),
        onMouseLeave: () => setHover(false),
      },
        h('span', {
          title: label,
          'aria-label': label,
          style: { ...dotStyle(tone), display: 'inline-block', cursor: 'help' },
        }),
        hover && label
          ? h('span', {
            style: {
              position: 'absolute',
              top: '18px',
              right: '0',
              zIndex: 30,
              width: 'max-content',
              maxWidth: '260px',
              padding: '5px 9px',
              borderRadius: '6px',
              background: 'var(--dsw-alias-bg-overlay)',
              border: '1px solid var(--dsw-alias-border-l2)',
              color: 'var(--dsw-alias-label-primary)',
              fontSize: '12px',
              lineHeight: '1.5',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.16)',
              pointerEvents: 'none',
              whiteSpace: 'normal',
            },
          }, label)
          : null,
      )
    }

    function Card(props) {
      const dots = Array.isArray(props.dots) ? props.dots.filter((dot) => dot && dot.title) : []
      const headRight = (props.extra || dots.length)
        ? h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '10px' } },
          props.extra ? h('span', { style: S.cardExtra }, props.extra) : null,
          dots.length
            ? h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '8px' } },
              dots.map((dot, index) => h(DotInfo, { key: `dot-${index}`, ...dot })))
            : null,
        )
        : null
      return h('section', { style: S.card },
        props.title
          ? h('div', { style: S.cardHead },
            h('h3', { style: S.cardTitle }, props.title),
            headRight,
          )
          : null,
        props.children,
      )
    }

    function ActionTile(props) {
      const disabled = props.disabled === true
      const [dotHover, setDotHover] = useState(false)
      // 四个动作框统一主色实心，**每个框自己的右上角**带一个信息点：
      //   重要 = 实心反色点、次要 = 空心圈、危险 = 红点。
      const dot = props.dot === 'danger' ? 'danger' : props.dot === 'secondary' ? 'secondary' : props.dot === 'primary' ? 'primary' : ''
      const dotLabel = dot === 'danger' ? '危险动作' : dot === 'secondary' ? '次要动作' : dot === 'primary' ? '重要动作' : ''
      const dotColor = dot === 'danger'
        ? { background: 'var(--dsw-alias-state-error-primary)', border: 'none' }
        : dot === 'secondary'
          ? { background: 'transparent', border: '2px solid var(--dsw-alias-bg-base)', opacity: 0.7 }
          : { background: 'var(--dsw-alias-bg-base)', border: 'none' }
      return h('button', {
        type: 'button',
        title: props.title || props.hint || '',
        style: disabled ? { ...S.tileSolid, ...S.buttonDisabled } : S.tileSolid,
        disabled,
        onClick: props.onClick,
      },
        dot
          ? h('span', {
            title: dotLabel,
            'aria-label': dotLabel,
            onMouseEnter: () => setDotHover(true),
            onMouseLeave: () => setDotHover(false),
            style: {
              position: 'absolute',
              top: '10px',
              right: '10px',
              width: '10px',
              height: '10px',
              boxSizing: 'border-box',
              borderRadius: '50%',
              cursor: 'help',
              ...dotColor,
            },
          },
            dotHover
              ? h('span', {
                style: {
                  position: 'absolute',
                  top: '16px',
                  right: '0',
                  zIndex: 30,
                  width: 'max-content',
                  padding: '4px 8px',
                  borderRadius: '6px',
                  background: 'var(--dsw-alias-bg-overlay)',
                  border: '1px solid var(--dsw-alias-border-l2)',
                  color: 'var(--dsw-alias-label-primary)',
                  fontSize: '12px',
                  fontWeight: 400,
                  lineHeight: '1.5',
                  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.16)',
                  pointerEvents: 'none',
                  whiteSpace: 'nowrap',
                },
              }, dotLabel)
              : null,
          )
          : null,
        h('span', null, props.label),
        h('span', { style: S.tileHintOnDark }, props.hint),
      )
    }

    /** 分区标题：把长面板切成几段，一眼看出「概览 / 操作 / 清理 / 校准 / 结果」。 */
    function SectionBar(props) {
      return h('div', { style: S.sectionBar },
        h('span', { style: S.sectionLabel }, props.label),
        h('span', { style: S.sectionLine }),
      )
    }

    function ErrorBanner(props) {
      return h('div', { style: { ...S.banner, ...S.bannerError } },
        h('p', { style: S.error }, props.children),
      )
    }

    function EmptyHint(props) {
      return h('p', { style: S.empty }, props.children)
    }

    /**
     * 垃圾 / 系统记忆分组卡片。
     * 垃圾组（kind=junk）带可勾选复选框与全选 / 反选；系统记忆组（kind=memory）只展示。
     */
    function JunkGroup(props) {
      const group = isObj(props.group) ? props.group : {}
      const groupId = text(group.id, `group-${props.index}`)
      const memory = props.memory === true || text(group.kind) === 'memory'
      const items = arr(group.items)
      const shown = items.slice(0, LIST_LIMIT)
      const totalCount = Math.max(num(group.itemCount), items.length)
      const remaining = Math.max(0, totalCount - shown.length)
      const selection = isObj(props.selection) ? props.selection : {}

      const rows = shown.map((item, itemIndex) => {
        const safeItem = isObj(item) ? item : {}
        const path = text(safeItem.path)
        const key = `${groupId}|${path || itemIndex}`
        const checked = memory !== true && selection[`${groupId}|${path}`] === true
        return h('label', { key, style: memory ? { ...S.itemRow, cursor: 'default' } : S.itemRow },
          h('input', {
            type: 'checkbox',
            style: S.checkbox,
            checked,
            disabled: memory,
            onChange: memory ? undefined : () => props.onToggleItem(groupId, path),
          }),
          h('span', { style: S.itemPath, title: path }, path || '（路径缺失）'),
          h('span', { style: S.itemSize }, formatBytes(num(safeItem.size))),
        )
      })

      return h('div', { style: S.groupCard },
        // 折叠态只有一行：分类名 + 大小/项数 + 展开；说明和明细都收进展开区。
        h('button', {
          type: 'button',
          style: S.groupHeadButton,
          'aria-expanded': props.expanded ? 'true' : 'false',
          onClick: props.onToggle,
        },
          h('span', { style: S.groupHeadText },
            h('span', { style: S.groupTitle }, `${props.expanded ? '▾' : '▸'} ${text(group.title, '未命名分类')}`),
            h('span', { style: S.groupMeta },
              `${formatBytes(num(group.totalBytes))} · ${totalCount} 项${memory ? ' · 系统记忆类' : ''}`),
          ),
          h('span', { style: S.tiny }, props.expanded ? '收起' : '展开'),
        ),
        props.expanded
          ? h('div', { style: S.groupBody },
            text(group.note) ? h('p', { style: S.hint }, text(group.note)) : null,
            memory ? h('p', { style: S.tiny }, '系统记忆类 · 仅查看，不删除') : null,
            memory
              ? null
              : h('div', { style: S.row },
                h('button', { type: 'button', style: S.linkButton, onClick: () => props.onSelectAll(group) }, '全选'),
                h('button', { type: 'button', style: S.linkButton, onClick: () => props.onInvert(group) }, '反选'),
              ),
            shown.length === 0
              ? h(EmptyHint, null, '这一组没有可列出的条目。')
              : h('div', { style: S.items }, rows),
            remaining > 0
              ? h('p', { style: S.tiny }, `还有 ${remaining} 项未显示（共 ${totalCount} 项，大小已计入统计）。`)
              : null,
          )
          : null,
      )
    }

    /** 面板渲染异常兜底：避免一个坏字段让整个 slot 空白。 */
    class PanelErrorBoundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { error: null }
      }

      static getDerivedStateFromError(error) {
        return { error }
      }

      componentDidCatch(error) {
        if (typeof console !== 'undefined' && typeof console.warn === 'function') {
          console.warn('[system-guard] 面板渲染出错：', error)
        }
      }

      render() {
        if (this.state.error) {
          return h('div', { style: S.panel },
            h('div', { style: S.scroller },
              h('div', { style: S.stack },
                h('div', { style: { ...S.banner, ...S.bannerError } },
                  h('p', { style: S.error },
                    `面板渲染出错：${messageOf(this.state.error)}。请刷新页面后重试。`),
                ),
              ),
            ),
          )
        }
        return this.props.children
      }
    }

    // ============================================================
    // 主面板
    // ============================================================
    function SystemGuardPanel() {
      const [state, setState] = useState(null)
      const [detail, setDetail] = useState(null)
      const [loading, setLoading] = useState(true)
      const [error, setError] = useState('')
      const [message, setMessage] = useState(null)
      const [taskId, setTaskId] = useState(null)
      const [task, setTask] = useState(null)
      const [busy, setBusy] = useState('')
      const [expanded, setExpanded] = useState({})
      const [selection, setSelection] = useState({})
      const [confirmDelete, setConfirmDelete] = useState(false)
      const [settingsDraft, setSettingsDraft] = useState(null)
      // 扫描警告默认折叠：警告通常只在排障时看，不占主视图。
      const [warningsOpen, setWarningsOpen] = useState(false)
      // 垃圾分类整卡默认折叠：主视图只留「垃圾合计 888 MB · N 项」一行。
      const [junkOpen, setJunkOpen] = useState(false)
      // 联网校准的详细结论/来源默认折叠：平时只看结论一行。
      const [calibrationOpen, setCalibrationOpen] = useState(false)

      const refresh = useCallback(async (options) => {
        const opts = isObj(options) ? options : {}
        if (opts.showSpinner === true) setLoading(true)
        try {
          const payload = await getJson('/state')
          setState(normalizeState(payload))
        } catch (err) {
          setError(messageOf(err))
        }
        try {
          const payload = await getJson('/analysis')
          setDetail(normalizeDetail(payload))
        } catch (err) {
          // 从未分析过时明细可能拿不到；首次加载不打扰，主动刷新 / 任务完成才提示。
          if (opts.reportDetailError === true) setError(messageOf(err))
        }
        setLoading(false)
      }, [])

      // 首次加载：状态 + 分析明细并行（明细失败不打断首屏）。
      useEffect(() => {
        refresh({ showSpinner: true }).catch(() => {})
      }, [refresh])

      // 长任务轮询：每 1.5s 一次，done / failed 后刷新并清理定时器。
      useEffect(() => {
        if (!taskId) return undefined
        let alive = true
        let timer = null

        const poll = async () => {
          try {
            const payload = await getJson(`/task?id=${encodeURIComponent(taskId)}`)
            if (!alive) return
            const nextTask = isObj(payload.task) ? payload.task : { state: 'running' }
            setTask(nextTask)
            const taskState = text(nextTask.state)
            if (taskState === 'done') {
              setTaskId(null)
              setBusy('')
              const kind = text(nextTask.kind)
              setMessage({ kind: 'ok', text: summarizeResult(kind, unwrapValue(nextTask.result)) })
              await refresh({ reportDetailError: true })
              return
            }
            if (taskState === 'failed') {
              setTaskId(null)
              setBusy('')
              setError(readError({ error: nextTask.error }, 0))
              await refresh({})
              return
            }
            // 取消等其它终态：任务已结束，别让轮询永远转下去。
            const stillRunning = taskState === '' || taskState === 'queued'
              || taskState === 'running' || taskState === 'pending' || taskState === 'cancelling'
            if (!stillRunning) {
              setTaskId(null)
              setBusy('')
              setMessage({
                kind: 'ok',
                text: taskState === 'cancelled' || taskState === 'canceled' || taskState === 'aborted'
                  ? '任务已取消。'
                  : '任务已结束。',
              })
              await refresh({ reportDetailError: true })
              return
            }
            timer = window.setTimeout(poll, POLL_MS)
          } catch (err) {
            if (!alive) return
            setTaskId(null)
            setBusy('')
            setError(messageOf(err))
          }
        }

        poll()
        return () => {
          alive = false
          if (timer) window.clearTimeout(timer)
        }
      }, [taskId, refresh])

      const runSync = useCallback(async (action, payload, describe, options) => {
        const opts = isObj(options) ? options : {}
        if (busy || taskId) return null
        setBusy(action)
        setError('')
        setMessage(null)
        try {
          const result = await postAction(action, payload)
          const value = unwrapValue(result)
          const successText = typeof describe === 'function' ? describe(value) : describe
          setMessage({ kind: 'ok', text: successText || '操作完成。' })
          await refresh({ reportDetailError: opts.reportDetailError === true })
          return value
        } catch (err) {
          setError(messageOf(err))
          return null
        } finally {
          setBusy('')
        }
      }, [busy, taskId, refresh])

      const startTask = useCallback(async (action, payload) => {
        if (busy || taskId) return
        setBusy(action)
        setError('')
        setMessage(null)
        try {
          const result = await postAction(action, payload)
          const id = text(result && result.taskId)
          if (id) {
            setTask({ id, kind: action, state: 'queued', stage: '', progress: 0 })
            setTaskId(id)
          } else {
            // 契约兜底：后端若把长任务同步做完，也按完成处理。
            const value = unwrapValue(result)
            setMessage({ kind: 'ok', text: summarizeResult(action, value) })
            await refresh({ reportDetailError: true })
          }
        } catch (err) {
          setError(messageOf(err))
        } finally {
          setBusy('')
        }
      }, [busy, taskId, refresh])

      /** 取消正在跑的长任务：后端会 abort 子进程，随后轮询会看到终态。 */
      const cancelTask = async () => {
        const id = taskId
        if (!id || busy === 'cancel-task') return
        setBusy('cancel-task')
        setError('')
        try {
          await postAction('cancel-task', { id })
          setMessage({ kind: 'ok', text: '已请求取消任务，正在等待它停下…' })
        } catch (err) {
          setError(messageOf(err))
        } finally {
          setBusy('')
        }
      }

      // ---------- 派生状态 ----------
      const running = taskId !== null
      const anyBusy = busy !== '' || running
      const stateData = state || {}
      const settings = isObj(stateData.settings) ? stateData.settings : {}
      const probe = isObj(stateData.probe) ? stateData.probe : null
      const privilege = isObj(stateData.privilege) ? stateData.privilege : {}
      const policy = isObj(stateData.policy) ? stateData.policy : {}
      const charter = isObj(policy.charter) ? policy.charter : {}
      const selfCheck = isObj(stateData.selfCheck) ? stateData.selfCheck : null
      const analysis = detail && isObj(detail.analysis) ? detail.analysis : null
      const junkGroups = detail ? detail.junkGroups : []
      const memoryGroups = detail ? detail.memoryGroups : []
      const junkTotalBytes = detail
        ? num(detail.junkTotalBytes) || sumGroupBytes(junkGroups) + sumGroupBytes(memoryGroups)
        : num(analysis && analysis.totalJunkBytes)
      const junkItemCount = sumGroupCount(junkGroups) + sumGroupCount(memoryGroups)
      const backup = isObj(stateData.backup) ? stateData.backup : null
      const patrol = isObj(stateData.lastPatrol) ? stateData.lastPatrol : null
      const calibration = isObj(stateData.lastCalibration) ? stateData.lastCalibration : null
      // 「当前是否管理员」可能是 false（普通 helper 进程），但用户已授权提权通道时，
      // 修复类动作仍可发起（每次都会弹一次 UAC 确认），所以两者取或。
      const adminNow = stateData.admin === true || privilege.granted === true
      const repairPaths = useMemo(() => collectRepairPaths(state), [state])
      const selectedItems = useMemo(() => collectSelectedItems(junkGroups, selection), [junkGroups, selection])
      const selectedBytes = selectedItems.reduce((sum, item) => sum + item.size, 0)

      const settingsValues = settingsDraft || {
        patrolIntervalDays: numberOrDefault(settings.patrolIntervalDays, 7),
        calibrateAskIntervalDays: numberOrDefault(settings.calibrateAskIntervalDays, 30),
      }

      // ---------- 交互 ----------
      const toggleExpanded = (groupId) => {
        setExpanded((current) => ({ ...current, [groupId]: current[groupId] !== true }))
      }

      const toggleItem = (groupId, path) => {
        if (!path) return
        const key = `${groupId}|${path}`
        setSelection((current) => {
          const next = { ...current }
          if (next[key] === true) delete next[key]
          else next[key] = true
          return next
        })
      }

      const selectGroup = (group, mode) => {
        if (!isObj(group)) return
        const groupId = text(group.id)
        const items = arr(group.items).slice(0, LIST_LIMIT)
        setSelection((current) => {
          const next = { ...current }
          for (const item of items) {
            if (!isObj(item) || typeof item.path !== 'string' || !item.path) continue
            const key = `${groupId}|${item.path}`
            if (mode === 'all') next[key] = true
            else if (next[key] === true) delete next[key]
            else next[key] = true
          }
          return next
        })
      }

      const grantPrivilege = () => {
        runSync('elevate', null, (value) => {
          const result = isObj(value) ? value : {}
          if (text(result.message)) return text(result.message)
          return result.granted === true ? '已获得管理员守护权限。' : '守护权限申请已处理。'
        }, { reportDetailError: false })
      }

      const verifyBackup = () => {
        runSync('backup-status', null, (value) => {
          const info = isObj(value) ? value : {}
          const backupState = text(info.state, 'unknown')
          const missing = arr(info.missingFiles).length
          const corrupt = arr(info.corruptFiles).length
          if (backupState === 'missing') return '校验结果：备份文件丢失，请重新备份。'
          if (backupState === 'partial') return `校验结果：备份不完整（缺失 ${missing} 个、损坏 ${corrupt} 个）。`
          if (backupState === 'none') return '还没有备份，请先点「立即备份」。'
          return '备份校验通过，文件齐全。'
        })
      }

      const startRepair = () => {
        if (anyBusy) return
        if (!adminNow) {
          setError(ERROR_HINTS['need-elevation'])
          return
        }
        if (repairPaths.length === 0) {
          setError('巡查结果里没有发现需要修复的缺失或损坏项。')
          return
        }
        startTask('repair', { mode: 'restore', paths: repairPaths })
      }

      const doDelete = async () => {
        const items = selectedItems.map((item) => ({ path: item.path }))
        setConfirmDelete(false)
        if (items.length === 0) return
        const value = await runSync('junk-delete', { confirm: true, items }, (report) => {
          const info = isObj(report) ? report : {}
          const deleted = arr(info.deleted).length
          const failed = arr(info.failed).length
          const freed = formatBytes(num(info.freedBytes))
          return `已删除 ${deleted} 项，释放 ${freed}${failed ? `；${failed} 项删除失败` : ''}。`
        }, { reportDetailError: true })
        if (value) setSelection({})
      }

      const saveSettings = () => {
        if (anyBusy) return
        const patch = {
          patrolIntervalDays: clampInt(settingsValues.patrolIntervalDays, 1, 365, num(settings.patrolIntervalDays) || 7),
          calibrateAskIntervalDays: clampInt(
            settingsValues.calibrateAskIntervalDays, 1, 365, num(settings.calibrateAskIntervalDays) || 30,
          ),
        }
        runSync('settings-save', { patch }, '设置已保存。').then((value) => {
          if (value) setSettingsDraft(null)
        })
      }

      const updateSettingsField = (key) => (event) => {
        const raw = event && event.target ? event.target.value : event
        setSettingsValues((current) => ({ ...current, [key]: raw }))
      }

      // React 不给 setState 传函数式？这里集中处理草稿合并，避免闭包陈旧。
      function setSettingsValues(updater) {
        setSettingsDraft((current) => {
          const base = current || settingsValues
          return updater(base)
        })
      }

      // ---------- 渲染 ----------
      const systemVolume = probe
        ? arr(probe.volumes).find((volume) => isObj(volume) && volume.isSystem === true)
          || arr(probe.volumes).find((volume) => isObj(volume) && text(volume.id) === text(probe.systemDrive))
        : null
      const maxFreeVolume = probe
        ? arr(probe.volumes).filter(isObj).reduce((best, volume) => {
          if (!best) return volume
          return num(volume.freeBytes) > num(best.freeBytes) ? volume : best
        }, null)
        : null
      const probeWarnings = probe ? arr(probe.warnings).filter((item) => text(item)) : []
      const detailWarnings = detail ? arr(detail.warnings).filter((item) => text(item)) : []
      // 同一次扫描的警告会同时出现在分析与垃圾两边，按文本去重后再展示，
      // 否则面板上会出现「prefetch、memory-dump」各两遍的重复警告。
      const allWarnings = [...new Set(probeWarnings.concat(detailWarnings).map((item) => text(item)))]
      // 扫描警告的说明：区分「本次已用管理员扫描」「已授权但没提权」「还没授权」三种情况，
      // 让用户知道下一步点哪里才能读到这些目录。
      const warningHint = allWarnings.length === 0
        ? ''
        : (analysis && analysis.elevated === true
          ? '本次扫描已使用管理员权限：下面这些目录仍然读不到，通常是系统或安全软件锁定，不影响使用。'
          : (privilege.granted === true
            ? '这些目录需要管理员权限才能读取。你已授权提权，点一次「分析」会自动用管理员权限重新扫描。'
            : '这些目录需要管理员权限才能读取。到「守护权限」点「授予守护权限」，再点「分析」就能扫到。'))

      const patrolChanges = patrol ? arr(patrol.changed).filter(isObj) : []
      const patrolMissing = patrol ? arr(patrol.missing).filter((path) => typeof path === 'string' && path.trim()) : []
      const exemptedChanges = patrolChanges.filter((change) => change.exempted === true)
      const realChanges = patrolChanges.filter((change) => change.exempted !== true)
      const patrolBadge = patrol ? verdictInfo(patrol.verdict) : null
      const missingShown = patrolMissing.slice(0, LIST_LIMIT)
      const sfc = patrol && isObj(patrol.sfc) ? patrol.sfc : null

      const calibrationFindings = calibration ? arr(calibration.findings).filter(isObj) : []
      const calibrationSources = calibration ? arr(calibration.sources).filter(isObj) : []
      const nextAskAt = stateData.nextCalibrateAskAt || null

      const backupStateText = backup ? text(backup.state, 'none') : 'none'
      const backupBroken = backupStateText === 'missing' || backupStateText === 'partial'

      const taskKindLabel = task ? text(KIND_LABEL[text(task.kind)], text(task.kind, '任务')) : '任务'
      const taskPercent = progressPercent(task && task.progress)
      const taskStage = text(task && task.stage) || '正在执行…'
      const cancelling = busy === 'cancel-task'

      const headerActions = h('div', { style: S.row },
        h('button', {
          type: 'button',
          style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
          disabled: anyBusy,
          onClick: () => { refresh({ showSpinner: true, reportDetailError: true }).catch(() => {}) },
        }, '刷新'),
      )

      const body = []

      // 顶部提示条
      if (error) body.push(h(ErrorBanner, { key: 'error' }, error))
      if (message) {
        body.push(h('div', { key: 'message', style: { ...S.banner, ...S.bannerOk } },
          h('p', { style: S.ok }, message.text || ''),
        ))
      }
      if (selfCheck && selfCheck.ok === false) {
        body.push(h('div', { key: 'selfcheck', style: { ...S.banner, ...S.bannerError } },
          h('p', { style: S.error },
            `${text(selfCheck.message, '插件核心代码自校验失败，写操作已被拒绝。')}`
            + `${arr(selfCheck.tampered).length ? `（被改动：${arr(selfCheck.tampered).join('、')}）` : ''}`),
        ))
      }
      if (loading && !state) {
        body.push(h(EmptyHint, { key: 'loading' }, '正在读取系统守护状态…'))
      }

      // 1. 系统信息
      body.push(h(SectionBar, { key: 'sec-overview', label: '概览' }))
      body.push(h(Card, { key: 'system', title: '系统信息', extra: probe ? text(probe.platform) : '' },
        probe
          ? h('div', { style: S.kv },
            h('span', { style: S.kvKey }, '操作系统'),
            h('span', { style: S.kvValue }, text(probe.osName, '未知系统')),
            h('span', { style: S.kvKey }, '版本 / build'),
            h('span', { style: S.kvValue }, `${text(probe.osVersion, '未知')} / build ${text(probe.osBuild, '未知')}`),
            h('span', { style: S.kvKey }, '架构'),
            h('span', { style: S.kvValue }, text(probe.arch, '未知')),
            h('span', { style: S.kvKey }, '当前权限'),
            h('span', { style: S.kvValue },
              probe.admin === true
                ? '管理员（当前进程）'
                : (privilege.granted === true
                  ? '普通用户 · 已授权提权（敏感操作时按系统的 UAC 设置弹窗或静默提升）'
                  : '普通用户（未授权提权）')),
            h('span', { style: S.kvKey }, '系统盘'),
            h('span', { style: S.kvValue }, describeVolume(systemVolume)),
            h('span', { style: S.kvKey }, '最大空闲盘'),
            h('span', { style: S.kvValue }, describeVolume(maxFreeVolume)),
            h('span', { style: S.kvKey }, '上次分析'),
            h('span', { style: S.kvValue },
              `${formatTime(analysis && analysis.analyzedAt)}`
              + `${analysis ? ` · 核心 ${num(analysis.coreCount)} 个 / 系统 ${num(analysis.supportCount)} 个` : ''}`
              + `${analysis && analysis.elevated === true ? ' · 管理员权限扫描' : ''}`),
            h('span', { style: S.kvKey }, '垃圾合计'),
            h('span', { style: S.kvValue }, `${formatBytes(junkTotalBytes)} · ${junkItemCount} 项`),
            h('span', { style: S.kvKey }, '基线来源'),
            h('span', { style: S.kvValue },
              text(stateData.baseline && stateData.baseline.source) === 'calibrated'
                ? '联网校准后的清单'
                : (calibration && calibration.ok
                  ? `内置清单（已于 ${formatTime(calibration.checkedAt)} 联网校准）`
                  : '内置清单')),
          )
          : h(EmptyHint, null, '还没有读取到系统信息，请点右上角「刷新」。'),
      ))

      // 2. 权限
      const grantedText = privilege.granted === true
        ? `已授予守护权限${privilege.grantedAt ? `（${formatTime(privilege.grantedAt)}）` : ''}`
        : '尚未授予守护权限'
      body.push(h(Card, {
        key: 'privilege',
        title: '守护权限',
        extra: probe && probe.admin === true ? '当前：管理员' : '当前：普通用户',
        dots: [{
          tone: 'primary',
          title: '重要动作：授予 / 重新申请守护权限',
        }],
      },
        h('p', { style: S.charter }, CHARTER_TEXT),
        text(charter.text) || text(policy.text)
          ? h('p', { style: S.hint }, text(charter.text) || text(policy.text))
          : null,
        h('div', { style: S.rowBetween },
          h('div', { style: S.row },
            h(Badge, { tone: privilege.granted === true || adminNow ? 'success' : 'muted' }, grantedText),
            h('span', { style: S.tiny }, `权限等级：${text(privilege.level, 'none')}`),
          ),
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
            disabled: anyBusy,
            onClick: grantPrivilege,
          }, busy === 'elevate' ? '等待用户确认…' : privilege.granted === true ? '重新申请守护权限' : '授予守护权限'),
        ),
        h('p', { style: S.tiny },
          '授予时 Windows 会请求管理员权限：UAC 默认弹确认框（最长等待 180 秒）；'
          + '如果系统 UAC 设成「不提示直接提升」，就会直接通过、不弹窗。'
          + '权限只用于分析、备份、巡查、修复这类保护动作；'
          + '它无法读取或上传你的个人文件，无法安装软件，也无法为其他程序提权。'),
        selfCheck && selfCheck.sealed === false
          ? h('p', { style: S.tiny }, '开发模式：插件尚未封存，核心代码未做哈希校验。')
          : null,
      ))

      // 3. 四个动作框统一主色实心，每个框自己的右上角带一个信息点（重要=实心、次要=空心、危险=红点）
      body.push(h(SectionBar, { key: 'sec-actions', label: '常用操作' }))
      body.push(h(Card, {
        key: 'actions',
        title: '守护动作',
        extra: running ? `任务进行中：${taskKindLabel}` : '',
      },
        h('div', { style: S.tileGrid },
          h(ActionTile, {
            label: '分析',
            hint: '扫描核心文件与系统垃圾分布',
            dot: 'primary',
            disabled: anyBusy,
            onClick: () => startTask('analyze'),
          }),
          h(ActionTile, {
            label: '维护',
            hint: `重扫系统垃圾分布、校验备份状态 · 上次 ${detail && detail.junk && detail.junk.scannedAt ? formatTime(detail.junk.scannedAt) : (patrol ? formatTime(patrol.checkedAt) : '从未维护')}`,
            dot: 'secondary',
            disabled: anyBusy,
            onClick: () => startTask('junk-scan'),
          }),
          h(ActionTile, {
            label: '巡查',
            hint: `立即核对核心文件完整性 · 上次 ${patrol ? formatTime(patrol.checkedAt) : '从未巡查'}`,
            dot: 'primary',
            disabled: anyBusy,
            onClick: () => startTask('patrol'),
          }),
          h(ActionTile, {
            label: '修复',
            hint: adminNow ? '从备份还原缺失或损坏的核心文件' : '需要管理员权限（先授予守护权限）',
            title: adminNow ? '' : '修复需要管理员权限',
            dot: 'danger',
            disabled: anyBusy,
            onClick: startRepair,
          }),
        ),
        running
          ? h('div', { style: S.groupBody },
            h('div', { style: S.rowBetween },
              h('span', { style: S.hint }, `${taskKindLabel}：${taskStage}`),
              h('div', { style: S.row },
                taskPercent === null ? null : h('span', { style: S.tiny }, `${Math.round(taskPercent)}%`),
                h('button', {
                  type: 'button',
                  style: cancelling ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
                  disabled: cancelling,
                  onClick: cancelTask,
                }, cancelling ? '正在取消…' : '取消任务'),
              ),
            ),
            h('div', { style: S.progressTrack },
              h('div', {
                style: {
                  ...S.progressFill,
                  width: `${taskPercent === null ? 30 : Math.max(2, taskPercent)}%`,
                  opacity: taskPercent === null ? 0.55 : 1,
                },
              }),
            ),
            h('p', { style: S.tiny }, '取消会中断当前系统命令；已完成的步骤不会回滚，稍后可以重新执行。'),
          )
          : null,
        h('p', { style: S.tiny },
          '「维护」重新扫描系统垃圾分布并刷新分类，方便你决定要不要清理；「巡查」逐个核对核心文件完整性。两者结果分别写在垃圾区与下方巡查结果区。'),
      ))

      // 4. 垃圾文件分类
      body.push(h(SectionBar, { key: 'sec-clean', label: '清理与备份' }))
      const junkSection = []
      if (!detail) {
        junkSection.push(h(EmptyHint, { key: 'junk-empty' },
          '还没有分析结果。第一次使用建议按这个顺序来：① 点「分析」建立核心文件基线并分类系统垃圾；'
          + '② 点「立即备份」保存一份核心系统文件；③ 点「巡查」核对完整性。分析只读取系统信息，不会改动任何文件。'))
      } else if (junkGroups.length === 0) {
        junkSection.push(h(EmptyHint, { key: 'junk-none' }, '没有发现可删除的垃圾文件。'))
      } else {
        junkSection.push(h('div', { key: 'junk-groups', style: S.groupBody },
          junkGroups.slice(0, 50).map((group, index) => h(JunkGroup, {
            key: text(group.id, `junk-${index}`),
            group,
            index,
            memory: false,
            expanded: expanded[text(group.id)] === true,
            selection,
            onToggle: () => toggleExpanded(text(group.id)),
            onToggleItem: toggleItem,
            onSelectAll: (target) => selectGroup(target, 'all'),
            onInvert: (target) => selectGroup(target, 'invert'),
          })),
        ))
      }

      if (memoryGroups.length) {
        junkSection.push(h('hr', { key: 'memory-divider', style: S.divider }))
        junkSection.push(h('p', { key: 'memory-title', style: S.sectionTitle }, '系统记忆类 · 仅查看，不删除'))
        junkSection.push(h('p', { key: 'memory-hint', style: S.tiny },
          '转储、休眠、崩溃日志等属于系统记忆，插件只展示、不参与删除，复选框为禁用状态。'))
        junkSection.push(h('div', { key: 'memory-groups', style: S.groupBody },
          memoryGroups.slice(0, 50).map((group, index) => h(JunkGroup, {
            key: text(group.id, `memory-${index}`),
            group,
            index,
            memory: true,
            expanded: expanded[text(group.id)] === true,
            selection,
            onToggle: () => toggleExpanded(text(group.id)),
            onToggleItem: toggleItem,
            onSelectAll: (target) => selectGroup(target, 'all'),
            onInvert: (target) => selectGroup(target, 'invert'),
          })),
        ))
      }

      const deleteBar = confirmDelete
        ? h('div', { style: S.confirmBar },
          h('p', { style: S.confirmText },
            `确认删除 ${selectedItems.length} 项（约 ${formatBytes(selectedBytes)}）？删除后不可恢复，确定继续吗？`),
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.buttonDangerSolid, ...S.buttonDisabled } : S.buttonDangerSolid,
            disabled: anyBusy,
            onClick: doDelete,
          }, '确认删除'),
          h('button', {
            type: 'button',
            style: S.buttonSecondary,
            onClick: () => setConfirmDelete(false),
          }, '取消'),
        )
        : h('div', { style: S.rowBetween },
          h('span', { style: S.hint }, `已选 ${selectedItems.length} 项 · 约 ${formatBytes(selectedBytes)}`),
          h('div', { style: S.row },
            h('button', {
              type: 'button',
              style: { ...S.buttonSecondary, ...S.buttonDisabled },
              disabled: true,
              title: '系统记忆类不参与删除',
            }, '系统记忆类不可删除'),
            h('button', {
              type: 'button',
              style: (!selectedItems.length || anyBusy) ? { ...S.buttonDanger, ...S.buttonDisabled } : S.buttonDanger,
              disabled: !selectedItems.length || anyBusy,
              onClick: () => setConfirmDelete(true),
            }, '删除选中项'),
          ),
        )

      const nonWindowsPlatform = text(stateData.platform) && text(stateData.platform) !== 'windows'
      body.push(h(Card, {
        key: 'junk',
        title: '垃圾文件分类',
        extra: `${formatBytes(junkTotalBytes)} · ${junkItemCount} 项`,
        // 这张卡里只有「删除」是危险动作，点放在它自己的右上角做信息标识。
        dots: [{ tone: 'danger', title: '删除选中项（危险动作，先展开再勾选，会二次确认）' }],
      },
        // 整卡折叠：默认只留一行「展开分类明细」，点开才看分组与打钩列表。
        h('button', {
          type: 'button',
          style: S.collapseBar,
          onClick: () => setJunkOpen((value) => !value),
          'aria-expanded': junkOpen === true,
        },
          h('span', { style: S.collapseBarText },
            h('span', { style: S.collapseBarCaret }, junkOpen ? '▾' : '▸'),
            h('span', null,
              junkOpen
                ? '分类明细已展开：勾选要清理的文件，再点「删除选中项」'
                : `展开分类明细（${junkGroups.length + memoryGroups.length} 组）—— 插件不会自动删除，由你打钩确认`),
          ),
          h('span', { style: S.collapseBarAction }, junkOpen ? '收起' : '展开'),
        ),
        junkOpen ? junkSection : null,
        junkOpen && nonWindowsPlatform
          ? h('p', { key: 'junk-platform-note', style: S.tiny },
            `当前系统（${text(stateData.platform)}）只做统计与分类：本插件不在该平台删除文件，需要清理请用系统自带的存储/清理工具。`)
          : null,
        junkOpen && !nonWindowsPlatform ? h('div', { style: S.deleteBar }, deleteBar) : null,
      ))

      // 5. 备份
      const backupRows = backup
        ? h('div', { style: S.kv },
          h('span', { style: S.kvKey }, '备份位置'),
          h('span', { style: S.kvValue }, text(backup.root, '未知')),
          h('span', { style: S.kvKey }, '所在磁盘'),
          h('span', { style: S.kvValue }, `${text(backup.volume, '未知')}${backup.hidden === true ? ' · 隐藏' : ' · 未隐藏'}`),
          h('span', { style: S.kvKey }, '文件数'),
          h('span', { style: S.kvValue }, `${num(backup.fileCount)} 个`),
          h('span', { style: S.kvKey }, '占用空间'),
          h('span', { style: S.kvValue }, formatBytes(num(backup.totalBytes))),
          h('span', { style: S.kvKey }, '创建时间'),
          h('span', { style: S.kvValue }, formatTime(backup.createdAt)),
          h('span', { style: S.kvKey }, '最近校验'),
          h('span', { style: S.kvValue }, formatTime(backup.verifiedAt)),
          h('span', { style: S.kvKey }, '状态'),
          h('span', { style: S.kvValue },
            backupStateText === 'ok' ? '正常'
              : backupStateText === 'partial' ? '不完整'
                : backupStateText === 'missing' ? '丢失' : '还没有备份'),
        )
        : h(EmptyHint, null, '还没有备份信息。点「立即备份」可以先把核心系统文件备份起来。')

      body.push(h(Card, {
        key: 'backup',
        title: '备份',
        extra: backupBroken ? '状态异常' : '',
        dots: [
          { tone: 'secondary', title: '次要动作：立即备份 / 校验备份 / 创建还原点' },
        ],
      },
        backupBroken
          ? h('div', { style: { ...S.banner, ...S.bannerError } },
            h('p', { style: S.error },
              backupStateText === 'missing'
                ? '备份文件丢失：备份清单还在，但备份目录里的文件不见了。建议立即重新备份。'
                : '备份不完整：部分文件缺失或损坏，建议重新备份并校验。'),
          )
          : null,
        backupRows,
        backup && (arr(backup.missingFiles).length || arr(backup.corruptFiles).length)
          ? h('p', { style: S.error },
            `备份缺失 ${arr(backup.missingFiles).length} 个文件、损坏 ${arr(backup.corruptFiles).length} 个文件。`)
          : null,
        h('div', { style: S.row },
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
            disabled: anyBusy,
            onClick: () => startTask('backup'),
          }, busy === 'backup' ? '备份中…' : '立即备份'),
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
            disabled: anyBusy,
            onClick: verifyBackup,
          }, busy === 'backup-status' ? '校验中…' : '校验备份'),
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
            disabled: anyBusy || !adminNow,
            onClick: () => startTask('restore-point'),
          }, busy === 'restore-point' ? '创建中…' : '创建系统还原点'),
        ),
        h('p', { style: S.tiny }, '备份默认放在剩余空间最大的固定盘下的隐藏目录里，并带冗余清单；删除检测只能发现并尽量恢复，不能物理阻止手动删除。'),
      ))

      // 6. 联网校准
      body.push(h(SectionBar, { key: 'sec-calibrate', label: '联网校准' }))
      body.push(h(Card, {
        key: 'calibrate',
        title: '联网校准',
        extra: calibration ? `上次 ${formatTime(calibration.checkedAt)}` : '从未校准',
        dots: [{
          tone: 'secondary',
          title: '次要动作：联网校准（只读查询官方渠道）',
        }],
      },
        h('div', { style: S.kv },
          h('span', { style: S.kvKey }, '上次校准'),
          h('span', { style: S.kvValue }, formatTime(calibration && calibration.checkedAt)),
          h('span', { style: S.kvKey }, '下次询问'),
          h('span', { style: S.kvValue },
            `${stateData.pendingCalibrationAsk ? '已到询问时间，建议现在校准' : formatTime(nextAskAt)}`),
        ),
        h('div', { style: S.row },
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
            disabled: anyBusy,
            onClick: () => startTask('calibrate'),
          }, busy === 'calibrate' ? '校准中…' : '立即联网校准'),
        ),
        calibration && text(calibration.summary)
          ? h('p', { style: S.body }, `结论：${text(calibration.summary)}`)
          : null,
        (calibrationFindings.length || calibrationSources.length)
          ? h('div', { style: S.groupBody },
            // 详细结论与来源默认收起：结论一行就够用，长清单想看时再展开。
            h('button', {
              type: 'button',
              style: S.collapseBar,
              onClick: () => setCalibrationOpen((value) => !value),
              'aria-expanded': calibrationOpen === true,
            },
              h('span', { style: S.collapseBarText },
                h('span', { style: S.collapseBarCaret }, calibrationOpen ? '▾' : '▸'),
                h('span', null,
                  calibrationOpen
                    ? '详细结论与官方来源'
                    : `详细结论与官方来源（${calibrationFindings.length} 条结论 / ${calibrationSources.length} 个来源）`),
              ),
              h('span', { style: S.collapseBarAction }, calibrationOpen ? '收起' : '展开'),
            ),
            calibrationOpen && calibrationFindings.length
              ? h('ul', { style: S.list },
                calibrationFindings.map((finding, index) => {
                  const tone = findingTone(finding.level)
                  const source = text(finding.source)
                  const full = text(finding.text, '（没有说明文字）')
                  return h('li', { key: `finding-${index}`, style: S.listItem },
                    h('span', { style: { color: TONE_COLOR[tone], fontWeight: 600 } }, `[${text(finding.level, 'info')}]`),
                    ' ',
                    // 个别限制说明会带很长的原始错误文本：截断显示，悬停看全文。
                    h('span', { title: full }, clipText(full)),
                    source
                      ? h('a', { href: source, target: '_blank', rel: 'noreferrer', style: S.link }, ' 官方来源')
                      : null,
                  )
                }),
              )
              : null,
            calibrationOpen && calibrationSources.length
              ? h('div', { style: S.groupBody },
                h('p', { style: S.sectionTitle }, '参考来源'),
                h('ul', { style: S.list },
                  calibrationSources.map((source, index) => {
                    const url = text(source.url)
                    return h('li', { key: `source-${index}`, style: S.listItem },
                      url
                        ? h('a', { href: url, target: '_blank', rel: 'noreferrer', style: S.link },
                          `${text(source.title, url)}（${url}）`)
                        : text(source.title, '来源缺少链接'),
                    )
                  }),
                ),
              )
              : null,
          )
          : h(EmptyHint, null, '还没有校准结论，点「立即联网校准」后用官方渠道核对系统文件版本。'),
        h('p', { style: S.tiny }, text(calibration && calibration.note,
          '校准 = 用官方发布信息核对系统版本 + 本地完整性验证，不是逐文件下载比对；官方站不提供逐文件哈希清单。')),
      ))

      // 7. 设置
      body.push(h(Card, {
        key: 'settings',
        title: '设置',
        dots: [{
          tone: 'secondary',
          title: '次要动作：保存设置',
        }],
      },
        h('div', { style: S.settingsGrid },
          h('label', { style: S.field },
            h('span', { style: S.fieldLabel }, '自动巡查间隔（天）'),
            h('input', {
              type: 'number',
              min: 1,
              max: 365,
              style: S.input,
              value: settingsValues.patrolIntervalDays,
              onChange: updateSettingsField('patrolIntervalDays'),
            }),
          ),
          h('label', { style: S.field },
            h('span', { style: S.fieldLabel }, '联网校准询问间隔（天）'),
            h('input', {
              type: 'number',
              min: 1,
              max: 365,
              style: S.input,
              value: settingsValues.calibrateAskIntervalDays,
              onChange: updateSettingsField('calibrateAskIntervalDays'),
            }),
          ),
        ),
        h('div', { style: S.row },
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
            disabled: anyBusy,
            onClick: saveSettings,
          }, busy === 'settings-save' ? '保存中…' : '保存设置'),
          h('span', { style: S.tiny }, `巡查间隔当前值 ${num(settings.patrolIntervalDays) || 7} 天 · 校准询问 ${num(settings.calibrateAskIntervalDays) || 30} 天`),
        ),
      ))

      // 8. 巡查结果
      const patrolCard = patrol
        ? h(Card, {
          key: 'patrol',
          title: '巡查结果',
          extra: `${formatTime(patrol.checkedAt)}${formatDuration(patrol.durationMs) ? ` · 用时 ${formatDuration(patrol.durationMs)}` : ''}`,
          dots: [{
            tone: 'danger',
            title: !adminNow
              ? '修复需要管理员权限：先在「守护权限」里授予权限'
              : repairPaths.length === 0
                ? '没有需要修复的项'
                : `修复 ${repairPaths.length} 个损坏/缺失项：从隐藏备份还原（危险操作）`,
            disabled: !adminNow || repairPaths.length === 0 || anyBusy,
            onClick: startRepair,
          }],
        },
          h('div', { style: S.row },
            h(Badge, { tone: patrolBadge.tone }, patrolBadge.text),
            h('span', { style: S.hint },
              `检查 ${num(patrol.total)} 项 · 未变 ${num(patrol.unchanged)} 项 · 变化 ${patrolChanges.length} 项 · 缺失 ${patrolMissing.length} 项`),
          ),
          exemptedChanges.length
            ? h('p', { style: S.tiny },
              `其中 ${exemptedChanges.length} 项变化落在最近的 Windows 更新窗口内，视为更新导致，已忽略、不修复。`)
            : null,
          realChanges.length
            ? h('div', { style: S.groupBody },
              h('p', { style: S.sectionTitle }, `非豁免变化（${realChanges.length} 项）`),
              h('ul', { style: S.list },
                realChanges.slice(0, LIST_LIMIT).map((change, index) => h('li', { key: `change-${index}`, style: S.listItem },
                  h('span', { style: S.mono }, shortSha(change.expectedSha)),
                  ' → ',
                  h('span', { style: S.mono }, shortSha(change.actualSha)),
                  ' ',
                  h('span', null, text(change.path, '（路径缺失）')),
                )),
                realChanges.length > LIST_LIMIT
                  ? h('li', { style: S.tiny }, `还有 ${realChanges.length - LIST_LIMIT} 项未显示。`)
                  : null,
              ),
            )
            : null,
          patrolMissing.length
            ? h('div', { style: S.groupBody },
              h('p', { style: S.sectionTitle }, `缺失的核心文件（${patrolMissing.length} 项）`),
              h('ul', { style: S.list },
                missingShown.map((path, index) => h('li', { key: `missing-${index}`, style: S.listItem }, path)),
                patrolMissing.length > LIST_LIMIT
                  ? h('li', { style: S.tiny }, `还有 ${patrolMissing.length - LIST_LIMIT} 项未显示。`)
                  : null,
              ),
            )
            : null,
          sfc
            ? h('p', { style: sfc.ran === true && sfc.passed === false ? S.error : S.hint },
              sfc.ran === true
                ? (sfc.passed === true
                  ? 'SFC 系统文件检查：通过'
                  : sfc.passed === false ? 'SFC 系统文件检查：发现问题' : 'SFC 系统文件检查：结果未知')
                : 'SFC 系统文件检查：本次未运行',
              text(sfc.detail) ? ` · ${text(sfc.detail)}` : '')
            : null,
          exemptedChanges.length
            ? h('div', { style: S.groupBody },
              h('p', { style: S.sectionTitle }, `豁免项（${exemptedChanges.length} 项）`),
              h('ul', { style: S.list },
                exemptedChanges.slice(0, LIST_LIMIT)
                  .map((change, index) => h('li', { key: `exempt-${index}`, style: S.listItem },
                    h('span', null, text(change.path, '（路径缺失）')),
                    ' · ',
                    h('span', { style: S.tiny }, 'Windows 更新导致，已忽略'),
                  )),
                exemptedChanges.length > LIST_LIMIT
                  ? h('li', { style: S.tiny }, `还有 ${exemptedChanges.length - LIST_LIMIT} 个豁免项未显示。`)
                  : null,
              ),
            )
            : null,
          h('div', { style: S.row },
            h('button', {
              type: 'button',
              style: (!adminNow || repairPaths.length === 0 || anyBusy)
                ? { ...S.button, ...S.buttonDisabled }
                : S.button,
              disabled: !adminNow || repairPaths.length === 0 || anyBusy,
              title: !adminNow ? '需要管理员权限' : repairPaths.length === 0 ? '没有需要修复的项' : '',
              onClick: startRepair,
            }, busy === 'repair' ? '修复中…' : `修复损坏项（${repairPaths.length}）`),
            h('span', { style: S.tiny },
              adminNow
                ? '从隐藏备份还原，只会写入巡查发现缺失或非豁免变化的系统文件。'
                : '修复需要管理员权限，请先在「守护权限」里点「授予守护权限」。'),
          ),
        )
        : h(Card, { key: 'patrol', title: '巡查结果' },
          h(EmptyHint, null, '还没有巡查结果。点上方「巡查」或「维护」核对核心文件完整性。'),
        )
      body.push(h(SectionBar, { key: 'sec-patrol', label: '巡查结果' }))
      body.push(patrolCard)

      // 9. 扫描警告：独立成一块、放在最后、默认折叠。
      // 这些只是「扫描时无权限访问的目录」，通常需要管理员权限，不代表系统损坏，
      // 所以不放进「系统信息」里占位置。
      if (allWarnings.length > 0) {
        body.push(h(SectionBar, { key: 'sec-diag', label: '诊断' }))
        body.push(h(Card, {
          key: 'warnings',
          title: '扫描警告',
          extra: `${allWarnings.length} 条`,
        },
          h('button', {
            type: 'button',
            style: S.collapseBar,
            onClick: () => setWarningsOpen((value) => !value),
            'aria-expanded': warningsOpen === true,
          },
            h('span', { style: S.collapseBarText },
              h('span', { style: S.collapseBarCaret }, warningsOpen ? '▾' : '▸'),
              h('span', null, '扫描时无法访问的目录 / 文件（通常需要管理员权限，不代表系统损坏）'),
            ),
            h('span', { style: S.collapseBarAction }, warningsOpen ? '收起' : '展开'),
          ),
          warningHint
            ? h('p', { style: S.tiny }, warningHint)
            : null,
          warningsOpen
            ? h('ul', { style: S.list },
              allWarnings.slice(0, 20).map((warning, index) => h('li', { key: `warn-${index}`, style: S.listItem }, text(warning))),
            )
            : null,
          warningsOpen && allWarnings.length > 20
            ? h('p', { style: S.tiny }, `还有 ${allWarnings.length - 20} 条警告未显示。`)
            : null,
        ))
      }

      // 结果区位置：巡查结果放在最后（要求 8），其余按 1~7 顺序。
      return h('div', { style: S.panel },
        h('div', { style: S.scroller },
          h('div', { style: S.stack },
            h('div', { style: S.header },
              h('div', { style: S.headerText },
                h('h2', { style: S.title }, '系统守护'),
                h('p', { style: S.subtitle },
                  '保护系统核心文件：分析、巡查、备份、修复。守护权限只用于保护系统，无法用于保护系统以外的事情。'),
                h('p', { style: S.tiny },
                  `版本 ${text(stateData.version, '未知')} · 平台 ${text(stateData.platform, '未知')}`),
                h('p', { style: S.tiny },
                  '分析只读取系统信息，不上传任何文件内容；垃圾文件不会自动删除，必须你打钩确认。'),
              ),
              headerActions,
            ),
            body,
          ),
        ),
      )
    }

    /** main 面板入口：外面包一层错误边界，避免坏数据让整个 slot 空白。 */
    function GuardPanelHost() {
      return h(PanelErrorBoundary, null, h(SystemGuardPanel))
    }

    // ============================================================
    // 插件注册
    // ============================================================
    return {
      inject: ['slots', 'layout'],

      apply(ctx) {
        /** 点侧栏图标时切到本面板（宿主行点击也会切，重复调用无副作用）。 */
        const openPanel = () => {
          try {
            if (ctx.layout && typeof ctx.layout.selectPanel === 'function') ctx.layout.selectPanel(PANEL_ID)
          } catch (error) {
            // 面板还没注册时 selectPanel 会抛错；宿主自己的行点击逻辑会兜住，这里不需要报错。
          }
        }

        /** 侧栏 16~24px 盾牌图标；props 由宿主提供 `{ size, active }`。 */
        function SidebarIcon(props) {
          const rawSize = Number(props && props.size)
          const size = clamp(Number.isFinite(rawSize) ? rawSize : 16, 12, 24)
          const active = Boolean(props && props.active)
          return h('svg', {
            viewBox: '0 0 24 24',
            width: size,
            height: size,
            xmlns: 'http://www.w3.org/2000/svg',
            'aria-hidden': 'true',
            focusable: 'false',
            style: { display: 'block', flex: 'none', cursor: 'pointer' },
            onClick: openPanel,
          },
            h('path', {
              d: 'M12 2.8 20 5.9v6.3c0 4.4-3.2 7.8-8 9.1-4.8-1.3-8-4.7-8-9.1V5.9z',
              fill: active ? 'var(--dsw-alias-brand-primary)' : 'var(--dsw-alias-label-secondary)',
              fillOpacity: active ? 0.22 : 0.1,
              stroke: 'currentColor',
              strokeWidth: 1.6,
              strokeLinejoin: 'round',
            }),
            h('path', {
              d: 'M8.4 12.3l2.4 2.4 4.6-5.1',
              fill: 'none',
              stroke: 'currentColor',
              strokeWidth: 1.8,
              strokeLinecap: 'round',
              strokeLinejoin: 'round',
            }),
          )
        }

        // 侧栏入口：id 与 main 的 key 必须一致，order 20 排在插件（0）与会话（…）之后。
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
          name: 'sidebar.panellist',
          id: PANEL_ID,
          order: 20,
          label: () => '系统守护',
        }, SidebarIcon))

        // 整页主面板：keyed slot，key = system-guard。
        ctx.slots.inject('main', () => ctx.slots.register({
          name: 'main',
          key: PANEL_ID,
        }, GuardPanelHost))
      },
    }
  },
})
