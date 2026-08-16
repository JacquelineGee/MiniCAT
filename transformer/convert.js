#!/usr/bin/env node
/**
 * convert.js — WXML → HTML 转换器
 *
 * 职责：
 *   1. 读取 WXML 文件
 *   2. 转换为 HTML（保留标签结构）
 *   3. 保留事件绑定信息（bindtap → data-event-tap, data-handler="xxx"）
 *   4. 输出 HTML 文件
 *
 * 用法：
 *   node convert.js <input.wxml> <output.html>
 */

import fs from 'fs';
import path from 'path';

/**
 * 简单的 WXML → HTML 转换器（不依赖外部库）
 *
 * 策略：
 *   - 将微信小程序标签映射为 HTML 标签（view → div, text → span 等）
 *   - 保留事件绑定：bindtap="handler" → data-event="tap" data-handler="handler"
 *   - 保留所有其他属性
 */
function convertWxmlToHtml(wxmlContent) {
  let html = wxmlContent;

  // 1. 标签映射（小程序组件 → HTML 标签）
  const tagMap = {
    'view': 'div',
    'text': 'span',
    'button': 'button',
    'image': 'img',
    'input': 'input',
    'textarea': 'textarea',
    'scroll-view': 'div',
    'swiper': 'div',
    'swiper-item': 'div',
    'picker': 'select',
    'navigator': 'a',
    'icon': 'i',
    'checkbox': 'input',
    'radio': 'input',
    'slider': 'input',
    'switch': 'input',
    'form': 'form',
    'label': 'label',
    'block': 'div',
    'web-view': 'iframe',
  };

  // 2. 事件绑定转换（bindtap, catchtap, bind:tap, catch:tap, bindchange 等）
  // bindtap="handler" → data-event="tap" data-handler="handler"
  // catchtap="handler" → data-event="tap" data-handler="handler" data-catch="true"
  // bind:tap="handler" → data-event="tap" data-handler="handler"
  const eventPattern = /(bind|catch):?(\w+)\s*=\s*["']([^"']+)["']/g;

  html = html.replace(eventPattern, (match, bindType, eventName, handlerName) => {
    const catchAttr = bindType === 'catch' ? ' data-catch="true"' : '';
    return `data-event="${eventName}" data-handler="${handlerName}"${catchAttr}`;
  });

  // 3. 标签替换（开标签和闭标签）
  for (const [wxTag, htmlTag] of Object.entries(tagMap)) {
    // 开标签：<view → <div
    html = html.replace(new RegExp(`<${wxTag}([\\s>])`, 'g'), `<${htmlTag}$1`);
    // 闭标签：</view> → </div>
    html = html.replace(new RegExp(`</${wxTag}>`, 'g'), `</${htmlTag}>`);
    // 自闭合标签：<view/> → <div/>
    html = html.replace(new RegExp(`<${wxTag}\\s*/>`, 'g'), `<${htmlTag}/>`);
  }

  // 4. 处理 wx:if, wx:for 等指令（保留为 data-wx-* 属性供 CodeQL 分析）
  html = html.replace(/wx:(\w+)\s*=\s*/g, 'data-wx-$1=');

  // 5. 处理反编译后的事件绑定（data-event-opts）
  // 反编译可能产生：data-event-opts='{"1234":[{"type":"tap","func":"__e"}]}'
  // 保留原样，后续 CodeQL 可以解析

  return html;
}

/**
 * 主函数
 */
function main() {
  const args = process.argv.slice(2);

  if (args.length < 2 || args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node convert.js <input.wxml> <output.html>');
    console.log('');
    console.log('Example:');
    console.log('  node convert.js pages/index/index.wxml pages/index/index.html');
    process.exit(args.includes('--help') || args.includes('-h') ? 0 : 1);
  }

  const [inputPath, outputPath] = args;

  // 检查输入文件
  if (!fs.existsSync(inputPath)) {
    console.error(`Error: Input file not found: ${inputPath}`);
    process.exit(1);
  }

  try {
    // 读取 WXML
    const wxmlContent = fs.readFileSync(inputPath, 'utf-8');

    // 转换
    const htmlContent = convertWxmlToHtml(wxmlContent);

    // 确保输出目录存在
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // 写入 HTML
    fs.writeFileSync(outputPath, htmlContent, 'utf-8');

    console.log(`✓ Converted: ${inputPath} → ${outputPath}`);
    process.exit(0);

  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

main();
